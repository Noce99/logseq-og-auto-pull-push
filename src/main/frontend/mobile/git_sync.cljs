(ns frontend.mobile.git-sync
  "Android-only: keeps the current graph folder in sync with a remote git repo
  over SSH. Pulls once on startup, then commits+pushes on an interval while
  the app is in the foreground (paused/resumed on backgrounding/foregrounding
  from frontend.mobile.core). Never force-pushes: on a real merge conflict,
  auto-push is paused and the user is told to resolve it manually (e.g. from
  the desktop app)."
  (:require ["@capacitor/core" :refer [registerPlugin]]
            [clojure.string :as string]
            [frontend.config :as config]
            [frontend.context.i18n :refer [t]]
            [frontend.handler.notification :as notification]
            [frontend.mobile.util :as mobile-util]
            [frontend.state :as state]
            [promesa.core :as p]))

;; NOTE: the `when` must wrap the whole `defonce`, not just the registerPlugin
;; call - `(defonce x (when test (registerPlugin ...)))` compiles to a ternary
;; and loses the type info :infer-externs needs to protect the plugin's method
;; names from advanced-mode renaming (they'd get minified and every call would
;; fail at runtime with "GitSync.<mangled-name>() is not implemented"). The
;; explicit ^js tag is a second, belt-and-suspenders safeguard.
(when (mobile-util/native-android?)
  (defonce ^js git-sync (registerPlugin "GitSync")))

(defonce ^:private *auto-push-interval-id (atom nil))
(defonce ^:private *syncing? (atom false))

(declare stop-auto-push-timer!)

(defn- strip-file-scheme
  [path]
  (if (string/starts-with? path "file://")
    (subs path (count "file://"))
    path))

(defn- current-repo-dir
  []
  (when-let [repo (state/get-current-repo)]
    (when (config/local-db? repo)
      (some-> (config/get-repo-dir repo) strip-file-scheme))))

(defn save-private-key!
  [private-key passphrase]
  (.savePrivateKey git-sync (clj->js {:privateKey private-key :passphrase (or passphrase "")})))

(defn has-private-key?
  []
  (p/let [ret (.hasPrivateKey git-sync)]
    (.-hasKey ^js ret)))

(defn clear-private-key!
  []
  (.clearPrivateKey git-sync))

(defn test-connection!
  [remote-url]
  (.testConnection git-sync (clj->js {:remoteUrl remote-url})))

(defn- show-error!
  [^js error fallback-msg-key]
  (let [code (.-code error)]
    (if (= code "MERGE_CONFLICT")
      (do
        (state/set-mobile-git-sync-cfgs! {:enabled? false :status :conflict})
        (stop-auto-push-timer!)
        (notification/show! (t :git-sync/conflict) :error false))
      (do
        (state/set-mobile-git-sync-cfgs! {:status :error :last-error (or (.-message error) (str error))})
        (notification/show! (t fallback-msg-key) :error)))))

(defn pull!
  "Pulls the remote into the current graph dir. Safe to call when git-sync
  isn't configured yet - it just resolves to nil."
  []
  (when (and git-sync (state/get-mobile-git-sync-remote-url))
    (when-let [dir (current-repo-dir)]
      (-> (.pull git-sync (clj->js {:repoDir dir :remoteUrl (state/get-mobile-git-sync-remote-url)}))
          (p/then (fn [_]
                    (state/set-mobile-git-sync-cfgs! {:status :ok :last-error nil :last-pulled-at (js/Date.now)})))
          (p/catch (fn [error] (show-error! error :git-sync/pull-failed)))))))

(defn commit-and-push!
  []
  (when (and git-sync (state/get-mobile-git-sync-remote-url) (not @*syncing?))
    (when-let [dir (current-repo-dir)]
      (reset! *syncing? true)
      (-> (.commitAndPush git-sync (clj->js {:repoDir dir :remoteUrl (state/get-mobile-git-sync-remote-url)}))
          (p/then (fn [_]
                    (state/set-mobile-git-sync-cfgs! {:status :ok :last-error nil :last-synced-at (js/Date.now)})))
          (p/catch (fn [error] (show-error! error :git-sync/push-failed)))
          (p/finally (fn [] (reset! *syncing? false)))))))

(defn sync-now!
  "Manual 'Sync now' button: pull then push."
  []
  (-> (pull!)
      (p/then commit-and-push!)))

(defn stop-auto-push-timer!
  []
  (when-let [id @*auto-push-interval-id]
    (js/clearInterval id)
    (reset! *auto-push-interval-id nil)))

(defn start-auto-push-timer!
  []
  (stop-auto-push-timer!)
  (when (and (mobile-util/native-android?)
             (state/get-mobile-git-sync-enabled?)
             (not (string/blank? (state/get-mobile-git-sync-remote-url))))
    (let [seconds (state/get-mobile-git-sync-interval-seconds)]
      (reset! *auto-push-interval-id
              (js/setInterval commit-and-push! (* 1000 seconds))))))
