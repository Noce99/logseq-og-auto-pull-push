package com.logseq.og;

import android.content.SharedPreferences;
import android.util.Log;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.UserInfo;

import org.eclipse.jgit.api.CreateBranchCommand;
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
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.PushResult;
import org.eclipse.jgit.transport.RemoteConfig;
import org.eclipse.jgit.transport.RemoteRefUpdate;
import org.eclipse.jgit.transport.SshSessionFactory;
import org.eclipse.jgit.transport.SshTransport;
import org.eclipse.jgit.transport.URIish;
import org.eclipse.jgit.transport.ssh.jsch.JschConfigSessionFactory;
import org.eclipse.jgit.transport.ssh.jsch.OpenSshConfig;
import org.eclipse.jgit.util.FS;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

/**
 * Keeps the currently-open graph folder in sync with a remote git repo over
 * SSH: {@link #pull} on startup, {@link #commitAndPush} on an interval driven
 * from the ClojureScript side. Never force-pushes: if the remote has diverged
 * in a way that can't be fast-forwarded/merged cleanly, calls reject with the
 * "MERGE_CONFLICT" error code and the JS side is expected to pause auto-sync
 * until the user resolves it (e.g. from the desktop app).
 *
 * Uses JGit's JSch-based SSH transport (org.eclipse.jgit.ssh.jsch), not the
 * Apache-MINA-sshd one (org.eclipse.jgit.ssh.apache) - MINA sshd hard-crashes
 * on Android in two different ways confirmed via on-device logcat:
 *  1. its ClientBuilder/PathUtils statically require a "user.home" system
 *     property, which Android never sets (IllegalArgumentException: No user
 *     home, inside ExceptionInInitializerError).
 *  2. its default key-exchange algorithm detection (Montgomery curve support
 *     probing) references javax.management.ReflectionException, which
 *     doesn't exist on Android (NoClassDefFoundError).
 * JSch is older/simpler and doesn't pull in either dependency.
 */
@CapacitorPlugin(name = "GitSync")
public class GitSyncPlugin extends Plugin {
    private static final String TAG = "Logseq/GitSync";
    private static final String PREFS_NAME = "git_sync_secure_prefs";
    private static final String KEY_PRIVATE_KEY = "private_key";
    private static final String KEY_PASSPHRASE = "passphrase";
    private static final String TRUSTED_HOSTS_FILE = "git_sync_trusted_hosts";
    // Without an explicit timeout a stalled SSH connection (bad network, a
    // server that never responds) hangs the calling thread forever - JGit's
    // TransportCommand.setTimeout(seconds) is respected by the JSch session.
    private static final int SSH_TIMEOUT_SECONDS = 20;

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
        try {
            TransportConfigCallback cb = buildTransportConfigCallback(loadKeyMaterial());
            Collection<Ref> refs = Git.lsRemoteRepository()
                    .setRemote(remoteUrl)
                    .setTransportConfigCallback(cb)
                    .setTimeout(SSH_TIMEOUT_SECONDS)
                    .call();
            JSObject ret = new JSObject();
            ret.put("ok", true);
            ret.put("refCount", refs.size());
            call.resolve(ret);
        } catch (Exception e) {
            Log.e(TAG, "testConnection failed", e);
            call.reject("Connection failed: " + e.getMessage());
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
        try (Git git = openOrInitRepo(repoDir, remoteUrl)) {
            TransportConfigCallback cb = buildTransportConfigCallback(loadKeyMaterial());

            boolean hadCommitBefore = git.getRepository().resolve("HEAD") != null;

            if (!hadCommitBefore) {
                // No local commits yet: fetch, then point HEAD/index at the
                // remote's default branch WITHOUT touching working-tree files,
                // so any pre-existing local graph files stay intact as
                // uncommitted changes to be picked up by the next commitAndPush.
                git.fetch().setTransportConfigCallback(cb).setTimeout(SSH_TIMEOUT_SECONDS).call();
                Ref remoteHead = findFirstRemoteBranch(git);
                if (remoteHead != null) {
                    // Point HEAD at a real local branch that tracks the
                    // remote one - not directly at the remote-tracking ref,
                    // which confuses JGit's pull machinery ("Cannot check
                    // out from unborn branch", confirmed on-device) since it
                    // expects HEAD to follow refs/heads/<name> to look up
                    // branch.<name>.{remote,merge} tracking config.
                    String shortName = Repository.shortenRefName(remoteHead.getName()); // e.g. "origin/main"
                    int slash = shortName.indexOf('/');
                    String localBranchName = slash >= 0 ? shortName.substring(slash + 1) : shortName;

                    git.branchCreate()
                            .setName(localBranchName)
                            .setStartPoint(remoteHead.getName())
                            .setUpstreamMode(CreateBranchCommand.SetupUpstreamMode.TRACK)
                            .call();
                    // Actually check the branch out (not just a MIXED reset,
                    // which only moves HEAD/index bookkeeping and never
                    // writes remote file content into the working directory -
                    // confirmed on-device: pull "succeeded" but no files
                    // appeared). A real checkout writes any file present in
                    // the remote commit but missing locally, and throws
                    // CheckoutConflictException (already handled below) if a
                    // pre-existing local file would be overwritten with
                    // different content - so this still can't silently clobber
                    // the user's existing graph.
                    git.checkout().setName(localBranchName).call();
                }
                resolveOk(call, false);
                return;
            }

            PullResult result = git.pull().setTransportConfigCallback(cb).setTimeout(SSH_TIMEOUT_SECONDS).call();
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
        try (Git git = openOrInitRepo(repoDir, remoteUrl)) {
            TransportConfigCallback cb = buildTransportConfigCallback(loadKeyMaterial());

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
                PullResult result = git.pull().setTransportConfigCallback(cb).setTimeout(SSH_TIMEOUT_SECONDS).call();
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
        }
    }

    // ---- internal helpers ------------------------------------------------

    private boolean isConflict(PullResult result) {
        MergeResult mergeResult = result.getMergeResult();
        return mergeResult != null && mergeResult.getMergeStatus() == MergeResult.MergeStatus.CONFLICTING;
    }

    private boolean attemptPush(Git git, TransportConfigCallback cb) throws GitAPIException {
        Iterable<PushResult> results = git.push().setTransportConfigCallback(cb).setTimeout(SSH_TIMEOUT_SECONDS).call();
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
        byte[] privateKeyBytes;
        byte[] passphraseBytes;
    }

    private SshKeyMaterial loadKeyMaterial() throws Exception {
        SharedPreferences prefs = securePrefs();
        String privateKey = prefs.getString(KEY_PRIVATE_KEY, null);
        String passphrase = prefs.getString(KEY_PASSPHRASE, "");
        if (privateKey == null) {
            throw new IllegalStateException("No SSH private key configured");
        }
        SshKeyMaterial material = new SshKeyMaterial();
        material.privateKeyBytes = privateKey.getBytes(StandardCharsets.UTF_8);
        material.passphraseBytes = passphrase.isEmpty() ? null : passphrase.getBytes(StandardCharsets.UTF_8);
        return material;
    }

    /**
     * Builds SSH transport config using JGit's JSch-based session factory,
     * with the private key supplied directly as in-memory bytes (JSch's
     * {@code addIdentity(name, prvkey, pubkey, passphrase)} overload) rather
     * than via any file on disk.
     */
    private TransportConfigCallback buildTransportConfigCallback(SshKeyMaterial key) {
        File trustedHostsFile = new File(getContext().getFilesDir(), TRUSTED_HOSTS_FILE);

        SshSessionFactory sessionFactory = new JschConfigSessionFactory() {
            @Override
            protected void configure(OpenSshConfig.Host hc, Session session) {
                // TrustOnFirstUseHostKeyRepository.check() below is the actual
                // enforcement point; "yes" just means "only OK from check()
                // is accepted", which is what we want.
                session.setConfig("StrictHostKeyChecking", "yes");
                session.setConfig("PreferredAuthentications", "publickey");
            }

            @Override
            protected JSch createDefaultJSch(FS fs) throws JSchException {
                JSch jsch = new JSch();
                jsch.setHostKeyRepository(new TrustOnFirstUseHostKeyRepository(trustedHostsFile));
                jsch.addIdentity("git-sync-key", key.privateKeyBytes, null, key.passphraseBytes);
                return jsch;
            }
        };

        return transport -> {
            if (transport instanceof SshTransport) {
                ((SshTransport) transport).setSshSessionFactory(sessionFactory);
            }
        };
    }

    /**
     * Trust-on-first-use host key verification: the first time we connect to
     * a host, its key is accepted and remembered in a persistent file. On
     * later connections, the presented key must match what's stored, or the
     * connection is rejected (protects against a key change after first
     * trust, e.g. MITM). All the trust logic lives in {@link #check}, which
     * returns only OK/CHANGED - never relies on JSch's own NOT_INCLUDED
     * handling, since that behaves inconsistently across JSch versions when
     * no interactive UserInfo prompt is available (as here, headless).
     */
    private static class TrustOnFirstUseHostKeyRepository implements HostKeyRepository {
        private final File trustedHostsFile;

        TrustOnFirstUseHostKeyRepository(File trustedHostsFile) {
            this.trustedHostsFile = trustedHostsFile;
        }

        @Override
        public synchronized int check(String host, byte[] key) {
            try {
                String encoded = Base64.getEncoder().encodeToString(key);
                List<String> lines = trustedHostsFile.exists()
                        ? Files.readAllLines(trustedHostsFile.toPath(), StandardCharsets.UTF_8)
                        : new ArrayList<>();
                for (String line : lines) {
                    int sp = line.indexOf(' ');
                    if (sp > 0 && line.substring(0, sp).equals(host)) {
                        return line.substring(sp + 1).equals(encoded) ? OK : CHANGED;
                    }
                }
                // first time seeing this host: trust and remember
                try (FileWriter fw = new FileWriter(trustedHostsFile, true)) {
                    fw.write(host + " " + encoded + "\n");
                }
                return OK;
            } catch (Exception e) {
                Log.e(TAG, "Host key trust check failed for " + host, e);
                return NOT_INCLUDED;
            }
        }

        @Override
        public void add(HostKey hostkey, UserInfo ui) {
            // no-op: persistence already handled in check()
        }

        @Override
        public void remove(String host, String type) {
        }

        @Override
        public void remove(String host, String type, byte[] key) {
        }

        @Override
        public String getKnownHostsRepositoryID() {
            return null;
        }

        @Override
        public HostKey[] getHostKey() {
            return new HostKey[0];
        }

        @Override
        public HostKey[] getHostKey(String host, String type) {
            return new HostKey[0];
        }
    }
}
