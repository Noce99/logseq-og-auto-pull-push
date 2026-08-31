package com.logseq.og;

// NOTE: this plugin was written and reviewed against JGit/Apache MINA sshd's
// documented API, but could not be compiled here (no Android SDK / JGit jars
// available in this environment). Build it in Android Studio first and fix
// any API mismatches against the exact JGit version pinned in build.gradle -
// the SSH transport wiring (buildTransportConfigCallback) is the part most
// likely to need small adjustments.

import android.content.SharedPreferences;
import android.util.Log;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.ListBranchCommand;
import org.eclipse.jgit.api.MergeResult;
import org.eclipse.jgit.api.PullResult;
import org.eclipse.jgit.api.ResetCommand;
import org.eclipse.jgit.api.Status;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.api.errors.CheckoutConflictException;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.lib.PersonIdent;
import org.eclipse.jgit.lib.Ref;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.PushResult;
import org.eclipse.jgit.transport.RemoteConfig;
import org.eclipse.jgit.transport.RemoteRefUpdate;
import org.eclipse.jgit.transport.SshTransport;
import org.eclipse.jgit.transport.URIish;
import org.eclipse.jgit.transport.sshd.JGitKeyCache;
import org.eclipse.jgit.transport.sshd.KeyPasswordProvider;
import org.eclipse.jgit.transport.sshd.ServerKeyDatabase;
import org.eclipse.jgit.transport.sshd.SshdSessionFactory;
import org.eclipse.jgit.transport.sshd.SshdSessionFactoryBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Keeps the currently-open graph folder in sync with a remote git repo over
 * SSH: {@link #pull} on startup, {@link #commitAndPush} on an interval driven
 * from the ClojureScript side. Never force-pushes: if the remote has diverged
 * in a way that can't be fast-forwarded/merged cleanly, calls reject with the
 * "MERGE_CONFLICT" error code and the JS side is expected to pause auto-sync
 * until the user resolves it (e.g. from the desktop app).
 */
@CapacitorPlugin(name = "GitSync")
public class GitSyncPlugin extends Plugin {
    private static final String TAG = "Logseq/GitSync";
    private static final String PREFS_NAME = "git_sync_secure_prefs";
    private static final String KEY_PRIVATE_KEY = "private_key";
    private static final String KEY_PASSPHRASE = "passphrase";
    private static final String TRUSTED_HOSTS_FILE = "git_sync_trusted_hosts";

    private JGitKeyCache keyCache;

    @Override
    protected void handleOnDestroy() {
        if (keyCache != null) {
            keyCache.close();
        }
    }

    // ---- Secure key storage (Keystore-backed, per-app-sandboxed) -----------

    private SharedPreferences securePrefs() throws Exception {
        MasterKey masterKey = new MasterKey.Builder(getContext())
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
        return EncryptedSharedPreferences.create(
                getContext(),
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
    }

    @PluginMethod()
    public void savePrivateKey(PluginCall call) {
        String privateKey = call.getString("privateKey");
        String passphrase = call.getString("passphrase", "");
        if (privateKey == null || privateKey.isEmpty()) {
            call.reject("privateKey is required");
            return;
        }
        try {
            securePrefs().edit()
                    .putString(KEY_PRIVATE_KEY, privateKey)
                    .putString(KEY_PASSPHRASE, passphrase)
                    .apply();
            call.resolve();
        } catch (Exception e) {
            Log.e(TAG, "savePrivateKey failed", e);
            call.reject("Failed to save private key: " + e.getMessage());
        }
    }

    @PluginMethod()
    public void hasPrivateKey(PluginCall call) {
        try {
            boolean has = securePrefs().contains(KEY_PRIVATE_KEY);
            JSObject ret = new JSObject();
            ret.put("hasKey", has);
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("Failed to read key store: " + e.getMessage());
        }
    }

    @PluginMethod()
    public void clearPrivateKey(PluginCall call) {
        try {
            securePrefs().edit()
                    .remove(KEY_PRIVATE_KEY)
                    .remove(KEY_PASSPHRASE)
                    .apply();
            call.resolve();
        } catch (Exception e) {
            call.reject("Failed to clear key: " + e.getMessage());
        }
    }

    // ---- Git operations ------------------------------------------------

    @PluginMethod()
    public void testConnection(PluginCall call) {
        String remoteUrl = call.getString("remoteUrl");
        if (remoteUrl == null || remoteUrl.isEmpty()) {
            call.reject("remoteUrl is required");
            return;
        }
        File sshDir = null;
        try {
            SshKeyMaterial key = loadKeyMaterial();
            sshDir = key.sshDir;
            TransportConfigCallback cb = buildTransportConfigCallback(key);
            Collection<Ref> refs = Git.lsRemoteRepository()
                    .setRemote(remoteUrl)
                    .setTransportConfigCallback(cb)
                    .call();
            JSObject ret = new JSObject();
            ret.put("ok", true);
            ret.put("refCount", refs.size());
            call.resolve(ret);
        } catch (Exception e) {
            Log.e(TAG, "testConnection failed", e);
            call.reject("Connection failed: " + e.getMessage());
        } finally {
            cleanupSshDir(sshDir);
        }
    }

    @PluginMethod()
    public void pull(PluginCall call) {
        String repoDir = call.getString("repoDir");
        String remoteUrl = call.getString("remoteUrl");
        if (repoDir == null || remoteUrl == null) {
            call.reject("repoDir and remoteUrl are required");
            return;
        }
        File sshDir = null;
        try (Git git = openOrInitRepo(repoDir, remoteUrl)) {
            SshKeyMaterial key = loadKeyMaterial();
            sshDir = key.sshDir;
            TransportConfigCallback cb = buildTransportConfigCallback(key);

            boolean hadCommitBefore = git.getRepository().resolve("HEAD") != null;

            if (!hadCommitBefore) {
                // No local commits yet: fetch, then point HEAD/index at the
                // remote's default branch WITHOUT touching working-tree files,
                // so any pre-existing local graph files stay intact as
                // uncommitted changes to be picked up by the next commitAndPush.
                git.fetch().setTransportConfigCallback(cb).call();
                Ref remoteHead = findFirstRemoteBranch(git);
                if (remoteHead != null) {
                    git.getRepository().updateRef("HEAD").link(remoteHead.getName());
                    git.reset()
                            .setMode(ResetCommand.ResetType.MIXED)
                            .setRef(remoteHead.getObjectId().getName())
                            .call();
                }
                resolveOk(call, false);
                return;
            }

            PullResult result = git.pull().setTransportConfigCallback(cb).call();
            if (!result.isSuccessful()) {
                if (isConflict(result)) {
                    abortConflictedMerge(git);
                    call.reject("Merge conflict while pulling", "MERGE_CONFLICT");
                } else {
                    call.reject("Pull failed: " + result);
                }
                return;
            }
            resolveOk(call, true);
        } catch (CheckoutConflictException e) {
            call.reject("Local changes conflict with remote", "MERGE_CONFLICT");
        } catch (Exception e) {
            Log.e(TAG, "pull failed", e);
            call.reject("Pull failed: " + e.getMessage());
        } finally {
            cleanupSshDir(sshDir);
        }
    }

    @PluginMethod()
    public void commitAndPush(PluginCall call) {
        String repoDir = call.getString("repoDir");
        String remoteUrl = call.getString("remoteUrl");
        if (repoDir == null || remoteUrl == null) {
            call.reject("repoDir and remoteUrl are required");
            return;
        }
        File sshDir = null;
        try (Git git = openOrInitRepo(repoDir, remoteUrl)) {
            SshKeyMaterial key = loadKeyMaterial();
            sshDir = key.sshDir;
            TransportConfigCallback cb = buildTransportConfigCallback(key);

            // `git add -A` equivalent: stage new/modified, then stage deletions.
            git.add().addFilepattern(".").call();
            git.add().addFilepattern(".").setUpdate(true).call();

            Status status = git.status().call();
            boolean committed = false;
            if (!status.isClean()) {
                git.commit()
                        .setAuthor(new PersonIdent("Logseq Android", "logseq-android-sync@localhost"))
                        .setMessage("Logseq auto-sync " + Instant.now())
                        .call();
                committed = true;
            }

            boolean pushed = attemptPush(git, cb);
            if (!pushed) {
                // Remote has diverged: try a safe merge, then retry the push once.
                // Never force-push.
                PullResult result = git.pull().setTransportConfigCallback(cb).call();
                if (!result.isSuccessful()) {
                    if (isConflict(result)) {
                        abortConflictedMerge(git);
                        call.reject("Merge conflict while syncing", "MERGE_CONFLICT");
                    } else {
                        call.reject("Pull-before-push failed: " + result);
                    }
                    return;
                }
                pushed = attemptPush(git, cb);
                if (!pushed) {
                    call.reject("Push rejected after retry", "PUSH_REJECTED");
                    return;
                }
            }

            JSObject ret = new JSObject();
            ret.put("committed", committed);
            ret.put("pushed", true);
            call.resolve(ret);
        } catch (Exception e) {
            Log.e(TAG, "commitAndPush failed", e);
            call.reject("Sync failed: " + e.getMessage());
        } finally {
            cleanupSshDir(sshDir);
        }
    }

    // ---- internal helpers ------------------------------------------------

    private boolean isConflict(PullResult result) {
        MergeResult mergeResult = result.getMergeResult();
        return mergeResult != null && mergeResult.getMergeStatus() == MergeResult.MergeStatus.CONFLICTING;
    }

    private boolean attemptPush(Git git, TransportConfigCallback cb) throws GitAPIException {
        Iterable<PushResult> results = git.push().setTransportConfigCallback(cb).call();
        for (PushResult result : results) {
            for (RemoteRefUpdate update : result.getRemoteUpdates()) {
                RemoteRefUpdate.Status status = update.getStatus();
                if (status == RemoteRefUpdate.Status.REJECTED_NONFASTFORWARD
                        || status == RemoteRefUpdate.Status.REJECTED_REMOTE_CHANGED) {
                    return false;
                }
            }
        }
        return true;
    }

    /** Best-effort approximation of `git merge --abort`. */
    private void abortConflictedMerge(Git git) {
        try {
            git.getRepository().writeMergeCommitMsg(null);
            git.getRepository().writeMergeHeads(null);
            git.reset().setMode(ResetCommand.ResetType.HARD).setRef("ORIG_HEAD").call();
        } catch (Exception e) {
            Log.e(TAG, "Failed to abort conflicted merge", e);
        }
    }

    private Ref findFirstRemoteBranch(Git git) {
        try {
            for (Ref ref : git.branchList().setListMode(ListBranchCommand.ListMode.REMOTE).call()) {
                if (!ref.getName().endsWith("/HEAD")) {
                    return ref;
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to list remote branches", e);
        }
        return null;
    }

    private Git openOrInitRepo(String repoDirPath, String remoteUrl) throws Exception {
        File dir = new File(repoDirPath);
        if (!dir.exists()) {
            throw new IllegalStateException("Graph directory does not exist: " + repoDirPath);
        }
        File gitDir = new File(dir, ".git");
        Git git = gitDir.exists() ? Git.open(dir) : Git.init().setDirectory(dir).call();
        ensureOrigin(git, remoteUrl);
        return git;
    }

    private void ensureOrigin(Git git, String remoteUrl) throws GitAPIException, java.net.URISyntaxException {
        List<RemoteConfig> remotes = git.remoteList().call();
        boolean hasOrigin = remotes.stream().anyMatch(r -> "origin".equals(r.getName()));
        if (!hasOrigin) {
            git.remoteAdd().setName("origin").setUri(new URIish(remoteUrl)).call();
        } else {
            git.remoteSetUrl().setRemoteName("origin").setRemoteUri(new URIish(remoteUrl)).call();
        }
    }

    private void resolveOk(PluginCall call, boolean pulled) {
        JSObject ret = new JSObject();
        ret.put("pulled", pulled);
        call.resolve(ret);
    }

    private static class SshKeyMaterial {
        File sshDir;
        Path keyPath;
        char[] passphrase;
    }

    /**
     * Trust-on-first-use host key verification: the first time we connect to
     * a host, its key is accepted and remembered in a persistent file (NOT
     * the per-call ephemeral ssh dir, which is wiped after every operation).
     * On later connections, the presented key must match what's stored, or
     * the connection is rejected (protects against a key change after first
     * trust, e.g. MITM). Without this, JGit's default "ask" policy has no
     * interactive prompt to fall back on and just rejects every unknown host
     * key outright, which surfaces as "Server key did not validate" /
     * "Remote hung up unexpectedly".
     */
    private static class TrustOnFirstUseServerKeyDatabase implements ServerKeyDatabase {
        private final File trustedHostsFile;

        TrustOnFirstUseServerKeyDatabase(File trustedHostsFile) {
            this.trustedHostsFile = trustedHostsFile;
        }

        @Override
        public List<PublicKey> lookup(String connectAddress, InetSocketAddress remoteAddress, Configuration config) {
            return Collections.emptyList();
        }

        @Override
        public synchronized boolean accept(String connectAddress, InetSocketAddress remoteAddress, PublicKey serverKey,
                                            Configuration config, CredentialsProvider provider) {
            try {
                String encoded = Base64.getEncoder().encodeToString(serverKey.getEncoded());
                List<String> lines = trustedHostsFile.exists()
                        ? Files.readAllLines(trustedHostsFile.toPath(), StandardCharsets.UTF_8)
                        : new ArrayList<>();
                for (String line : lines) {
                    int sp = line.indexOf(' ');
                    if (sp > 0 && line.substring(0, sp).equals(connectAddress)) {
                        return line.substring(sp + 1).equals(encoded);
                    }
                }
                try (FileWriter fw = new FileWriter(trustedHostsFile, true)) {
                    fw.write(connectAddress + " " + encoded + "\n");
                }
                return true;
            } catch (Exception e) {
                Log.e(TAG, "Host key trust check failed for " + connectAddress, e);
                return false;
            }
        }
    }

    private SshKeyMaterial loadKeyMaterial() throws Exception {
        SharedPreferences prefs = securePrefs();
        String privateKey = prefs.getString(KEY_PRIVATE_KEY, null);
        String passphrase = prefs.getString(KEY_PASSPHRASE, "");
        if (privateKey == null) {
            throw new IllegalStateException("No SSH private key configured");
        }

        File sshDir = new File(getContext().getFilesDir(), "git-ssh-" + System.nanoTime());
        sshDir.mkdirs();
        File keyFile = new File(sshDir, "id_key");
        try (FileOutputStream fos = new FileOutputStream(keyFile)) {
            fos.write(privateKey.getBytes(StandardCharsets.UTF_8));
        }
        // best-effort 600 perms: owner read/write only
        keyFile.setReadable(false, false);
        keyFile.setReadable(true, true);
        keyFile.setWritable(false, false);
        keyFile.setWritable(true, true);

        SshKeyMaterial material = new SshKeyMaterial();
        material.sshDir = sshDir;
        material.keyPath = keyFile.toPath();
        material.passphrase = passphrase.isEmpty() ? new char[0] : passphrase.toCharArray();
        return material;
    }

    /**
     * Builds SSH transport config pointed at an in-memory-supplied key file
     * (via {@link SshdSessionFactoryBuilder#setDefaultIdentities}), rather than
     * relying on filename conventions under ~/.ssh.
     */
    private TransportConfigCallback buildTransportConfigCallback(SshKeyMaterial key) {
        if (keyCache == null) {
            keyCache = new JGitKeyCache();
        }
        Path keyPath = key.keyPath;
        char[] passphrase = key.passphrase;

        File trustedHostsFile = new File(getContext().getFilesDir(), TRUSTED_HOSTS_FILE);

        SshdSessionFactory sessionFactory = new SshdSessionFactoryBuilder()
                .setPreferredAuthentications("publickey")
                .setHomeDirectory(key.sshDir)
                .setSshDirectory(key.sshDir)
                .setDefaultIdentities(dir -> Collections.singletonList(keyPath))
                .setServerKeyDatabase((home, ssh) -> new TrustOnFirstUseServerKeyDatabase(trustedHostsFile))
                .setKeyPasswordProvider(cp -> new KeyPasswordProvider() {
                    @Override
                    public char[] getPassphrase(URIish uri, int attempt) {
                        return passphrase.length == 0 ? null : passphrase;
                    }

                    @Override
                    public void setAttempts(int maxNumberOfAttempts) {
                        // no-op: passphrase is fixed for the lifetime of this call
                    }

                    @Override
                    public boolean keyLoaded(URIish uri, int attempt, Exception error) {
                        return false; // do not retry/prompt
                    }
                })
                .build(keyCache);

        return transport -> {
            if (transport instanceof SshTransport) {
                ((SshTransport) transport).setSshSessionFactory(sessionFactory);
            }
        };
    }

    private void cleanupSshDir(File sshDir) {
        if (sshDir == null) {
            return;
        }
        try {
            File[] files = sshDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    f.delete();
                }
            }
            sshDir.delete();
        } catch (Exception e) {
            Log.w(TAG, "Failed to clean up temp ssh dir", e);
        }
    }
}
