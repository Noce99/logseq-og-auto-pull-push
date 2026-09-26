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
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectLoader;
import org.eclipse.jgit.lib.ObjectReader;
import org.eclipse.jgit.lib.PersonIdent;
import org.eclipse.jgit.lib.Ref;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.transport.PushResult;
import org.eclipse.jgit.transport.RemoteConfig;
import org.eclipse.jgit.transport.RemoteRefUpdate;
import org.eclipse.jgit.transport.SshSessionFactory;
import org.eclipse.jgit.transport.SshTransport;
import org.eclipse.jgit.transport.URIish;
import org.eclipse.jgit.transport.ssh.jsch.JschConfigSessionFactory;
import org.eclipse.jgit.transport.ssh.jsch.OpenSshConfig;
import org.eclipse.jgit.treewalk.TreeWalk;
import org.eclipse.jgit.util.FS;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    // Repo .git dirs already swept for leftover locks by this process. Static:
    // Capacitor makes a new plugin instance when the Activity is recreated.
    private static final Set<String> CLEANED_REPOS = new HashSet<>();

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
                performColdStart(git, cb);
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
        } catch (CheckoutConflictException | ColdStartConflictException e) {
            call.reject("Local changes conflict with remote", "MERGE_CONFLICT");
        } catch (Exception e) {
            Log.e(TAG, "pull failed", e);
            call.reject("Pull failed: " + e.getMessage());
        }
    }

    /**
     * Explicit "Clone repo" action from settings: unlike {@link #pull}, this
     * creates {@code repoDir} if it doesn't exist yet (e.g. the user deleted
     * the graph folder and wants to bring it back from the remote), then runs
     * the same safe cold-start materialization. If the directory already has
     * commits (e.g. clone was already done), falls back to a normal pull.
     */
    @PluginMethod()
    public void cloneRepo(PluginCall call) {
        String repoDir = call.getString("repoDir");
        String remoteUrl = call.getString("remoteUrl");
        if (repoDir == null || remoteUrl == null) {
            call.reject("repoDir and remoteUrl are required");
            return;
        }
        File dir = new File(repoDir);
        if (!dir.exists() && !dir.mkdirs()) {
            call.reject("Failed to create graph directory: " + repoDir);
            return;
        }
        try (Git git = openOrInitRepo(repoDir, remoteUrl)) {
            TransportConfigCallback cb = buildTransportConfigCallback(loadKeyMaterial());

            boolean hadCommitBefore = git.getRepository().resolve("HEAD") != null;
            if (hadCommitBefore) {
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
                return;
            }

            performColdStart(git, cb);
            resolveOk(call, true);
        } catch (CheckoutConflictException | ColdStartConflictException e) {
            call.reject("Local changes conflict with remote", "MERGE_CONFLICT");
        } catch (Exception e) {
            Log.e(TAG, "cloneRepo failed", e);
            call.reject("Clone failed: " + e.getMessage());
        }
    }

    /**
     * Fetches and, if the remote has any branch, safely materializes its
     * default branch's tree into the (possibly non-empty) working directory -
     * see {@link #materializeColdStart}. Used for the initial "no local
     * commits yet" case, shared by {@link #pull} and {@link #cloneRepo}.
     */
    private void performColdStart(Git git, TransportConfigCallback cb)
            throws GitAPIException, IOException, ColdStartConflictException {
        git.fetch().setTransportConfigCallback(cb).setTimeout(SSH_TIMEOUT_SECONDS).call();
        Ref remoteHead = findFirstRemoteBranch(git);
        if (remoteHead == null) {
            return;
        }
        // Point HEAD at a real local branch that tracks the remote one - not
        // directly at the remote-tracking ref, which confuses JGit's pull
        // machinery ("Cannot check out from unborn branch", confirmed
        // on-device) since it expects HEAD to follow refs/heads/<name> to
        // look up branch.<name>.{remote,merge} tracking config.
        String shortName = Repository.shortenRefName(remoteHead.getName()); // e.g. "origin/main"
        int slash = shortName.indexOf('/');
        String localBranchName = slash >= 0 ? shortName.substring(slash + 1) : shortName;

        // setForce(true): idempotent against a previous cold-start attempt
        // that created this branch but then failed before HEAD ever became
        // "born" - confirmed on-device: RefAlreadyExistsException on retry
        // without this.
        git.branchCreate()
                .setName(localBranchName)
                .setStartPoint(remoteHead.getName())
                .setUpstreamMode(CreateBranchCommand.SetupUpstreamMode.TRACK)
                .setForce(true)
                .call();

        // Materialize the remote's files ourselves (scan fully for conflicts
        // BEFORE writing anything) instead of using git.checkout(), which
        // turned out to NOT be atomic on conflict: confirmed on-device it can
        // delete/overwrite unrelated working-tree files before throwing on
        // the file that actually conflicts. See materializeColdStart.
        RevCommit remoteCommit;
        try (RevWalk revWalk = new RevWalk(git.getRepository())) {
            remoteCommit = revWalk.parseCommit(remoteHead.getObjectId());
        }
        materializeColdStart(git.getRepository(), remoteCommit, git.getRepository().getWorkTree());

        String localRef = "refs/heads/" + localBranchName;
        git.getRepository().updateRef("HEAD").link(localRef);
        // Working tree now matches the remote commit exactly
        // (pre-existing-and-identical files untouched, missing ones just
        // written) - a MIXED reset only needs to update index/HEAD
        // bookkeeping to match, no more file writes.
        git.reset().setMode(ResetCommand.ResetType.MIXED).setRef(localRef).call();
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

    private static class ColdStartConflictException extends Exception {
        ColdStartConflictException(String message) {
            super(message);
        }
    }

    /**
     * Safely brings the working directory in line with {@code remoteCommit}'s
     * tree, for the case where there's no local commit yet but there may be
     * pre-existing, untracked local files: scans the ENTIRE remote tree
     * first, comparing every path against the working directory - a path
     * that exists locally with different content is a conflict. Nothing is
     * written to disk unless the full scan finds zero conflicts, so unlike
     * git.checkout() (confirmed on-device to delete/overwrite files before
     * throwing on the one that actually conflicts) this can never partially
     * apply.
     */
    private void materializeColdStart(Repository repo, RevCommit remoteCommit, File workDir)
            throws IOException, ColdStartConflictException {
        List<String> conflicts = new ArrayList<>();
        Map<String, ObjectId> toWrite = new LinkedHashMap<>();

        try (TreeWalk treeWalk = new TreeWalk(repo);
             ObjectReader reader = repo.newObjectReader()) {
            treeWalk.addTree(remoteCommit.getTree());
            treeWalk.setRecursive(true);
            while (treeWalk.next()) {
                String path = treeWalk.getPathString();
                File localFile = new File(workDir, path);
                if (!localFile.isFile()) {
                    toWrite.put(path, treeWalk.getObjectId(0));
                    continue;
                }
                ObjectLoader loader = reader.open(treeWalk.getObjectId(0));
                if (!Arrays.equals(loader.getBytes(), Files.readAllBytes(localFile.toPath()))) {
                    conflicts.add(path);
                }
            }

            if (!conflicts.isEmpty()) {
                throw new ColdStartConflictException(
                        conflicts.size() + " local file(s) differ from remote: " + conflicts);
            }

            for (Map.Entry<String, ObjectId> entry : toWrite.entrySet()) {
                File target = new File(workDir, entry.getKey());
                File parent = target.getParentFile();
                if (parent != null) {
                    parent.mkdirs();
                }
                Files.write(target.toPath(), reader.open(entry.getValue()).getBytes());
            }
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
        removeLeftoverLocks(gitDir);
        Git git = gitDir.exists() ? Git.open(dir) : Git.init().setDirectory(dir).call();
        ensureOrigin(git, remoteUrl);
        return git;
    }

    /**
     * If the app is killed mid-operation (swiped away, MIUI killing it during
     * an auto-push, an APK update), JGit leaves *.lock files behind (index,
     * config, refs...) and every later pull/commit fails with
     * LockFailedException forever - confirmed on-device, sync was silently
     * blocked for weeks by a leftover index.lock. All git calls here run one
     * at a time on the plugin's thread in this process, so any lock present
     * before this process first touches a repo is from a dead process.
     */
    private void removeLeftoverLocks(File gitDir) {
        synchronized (CLEANED_REPOS) {
            if (!gitDir.isDirectory() || !CLEANED_REPOS.add(gitDir.getAbsolutePath())) {
                return;
            }
        }
        deleteLockFiles(gitDir);
    }

    private static void deleteLockFiles(File dir) {
        File[] children = dir.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                if (!child.getName().equals("objects")) {
                    deleteLockFiles(child);
                }
            } else if (child.getName().endsWith(".lock")) {
                Log.w(TAG, "Removing leftover lock " + child);
                if (!child.delete()) {
                    Log.e(TAG, "Failed to remove leftover lock " + child);
                }
            }
        }
    }

    private void ensureOrigin(Git git, String remoteUrl) throws GitAPIException, java.net.URISyntaxException {
        URIish uri = new URIish(remoteUrl);
        List<RemoteConfig> remotes = git.remoteList().call();
        RemoteConfig origin = remotes.stream().filter(r -> "origin".equals(r.getName())).findFirst().orElse(null);
        if (origin == null) {
            git.remoteAdd().setName("origin").setUri(uri).call();
        } else if (!origin.getURIs().equals(Collections.singletonList(uri))) {
            // Only rewrite .git/config when the URL actually changed - this
            // runs on every pull/push, and each write is another chance for a
            // kill to leave config.lock behind.
            git.remoteSetUrl().setRemoteName("origin").setRemoteUri(uri).call();
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
