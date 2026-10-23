//! One update timer belongs to the whole client lifecycle, across reconnects.
use crate::settings::UpdateSettings;
use std::{collections::HashSet, future::Future, time::Duration};
use tokio::{sync::watch, time::Instant};

pub(crate) async fn run(settings: &UpdateSettings, online: watch::Receiver<bool>) {
    let options = settings.options();
    schedule(
        Duration::from_secs(settings.interval_hours * 60 * 60),
        online,
        || async {
            // Automatic failures and up-to-date results have no visible output.
            crate::update::check_latest(&options)
                .await
                .map(|release| release.map(|release| release.version))
                .map_err(|_| ())
        },
        |version| {
            log::info!(
                "New drcom4scut version {version} is available. Run drcom4scut --update to install."
            );
        },
    )
    .await;
}

async fn schedule<Check, Checked, Notify>(
    interval: Duration,
    mut online: watch::Receiver<bool>,
    mut check: Check,
    mut notify: Notify,
) where
    Check: FnMut() -> Checked,
    Checked: Future<Output = Result<Option<String>, ()>>,
    Notify: FnMut(&str),
{
    while !*online.borrow_and_update() {
        if online.changed().await.is_err() {
            return;
        }
    }
    // Reconnecting never resets this first-success deadline or starts a timer.
    let mut deadline = Instant::now() + Duration::from_secs(60);
    let mut notified = HashSet::new();
    loop {
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                result = online.changed() => if result.is_err() { return; },
            }
        }
        // A due check waits for a confirmed complete connection. Failed initial
        // authentication, the EAP stage of full mode and offline retries do not
        // cause update requests.
        while !*online.borrow_and_update() {
            if online.changed().await.is_err() {
                return;
            }
        }
        deadline = Instant::now() + interval;
        if let Ok(Some(version)) = check().await
            && notified.insert(version.clone())
        {
            notify(&version);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    async fn tick(seconds: u64) {
        tokio::time::advance(Duration::from_secs(seconds)).await;
        tokio::task::yield_now().await;
    }

    #[tokio::test(start_paused = true)]
    async fn selected_authentication_mode_controls_when_the_update_timer_can_begin() {
        for no_udp in [false, true] {
            let (online, receiver) = watch::channel(false);
            let checks = Arc::new(AtomicUsize::new(0));
            let observed = checks.clone();
            let task = tokio::spawn(schedule(
                Duration::from_secs(24 * 60 * 60),
                receiver,
                move || {
                    observed.fetch_add(1, Ordering::SeqCst);
                    async { Ok(None) }
                },
                |_| panic!("up-to-date checks must be silent"),
            ));
            tokio::task::yield_now().await;
            online.send_replace(crate::client::complete_online(no_udp, true, false));
            tokio::task::yield_now().await;
            tick(60).await;
            // EAP is complete for explicit EAP-only, and intermediate for full
            // mode. Full mode still needs its authenticated UDP heartbeat.
            assert_eq!(checks.load(Ordering::SeqCst), usize::from(no_udp));
            if !no_udp {
                online.send_replace(crate::client::complete_online(false, true, true));
                tokio::task::yield_now().await;
                tick(59).await;
                assert_eq!(checks.load(Ordering::SeqCst), 0);
                tick(1).await;
                assert_eq!(checks.load(Ordering::SeqCst), 1);
            }
            task.abort();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn first_complete_online_starts_one_minute_timer_across_reconnects() {
        let (online, receiver) = watch::channel(false);
        let checks = Arc::new(AtomicUsize::new(0));
        let observed = checks.clone();
        let task = tokio::spawn(schedule(
            Duration::from_secs(24 * 60 * 60),
            receiver,
            move || {
                observed.fetch_add(1, Ordering::SeqCst);
                async { Ok(None) }
            },
            |_| panic!("up-to-date checks must be silent"),
        ));
        tokio::task::yield_now().await;
        // Offline retries and intermediate authentication cannot start a timer.
        tick(240).await;
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        online.send_replace(true);
        tokio::task::yield_now().await;
        tick(20).await;
        online.send_replace(false);
        tokio::task::yield_now().await;
        tick(20).await;
        online.send_replace(true);
        tokio::task::yield_now().await;
        tick(19).await;
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        tick(1).await;
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        online.send_replace(false);
        tokio::task::yield_now().await;
        online.send_replace(true);
        tick(60).await;
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn due_checks_wait_for_online_and_periodic_results_only_notify_once_per_version() {
        let (online, receiver) = watch::channel(true);
        let checks = Arc::new(AtomicUsize::new(0));
        let observed = checks.clone();
        let notifications = Arc::new(Mutex::new(Vec::new()));
        let notices = notifications.clone();
        let task = tokio::spawn(schedule(
            Duration::from_secs(24 * 60 * 60),
            receiver,
            move || {
                let attempt = observed.fetch_add(1, Ordering::SeqCst);
                async move {
                    match attempt {
                        0 => Err(()),
                        1 => Ok(None),
                        _ => Ok(Some("1.2.3".to_owned())),
                    }
                }
            },
            move |version| notices.lock().unwrap().push(version.to_owned()),
        ));
        tokio::task::yield_now().await;
        online.send_replace(false);
        tick(60).await;
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        online.send_replace(true);
        tokio::task::yield_now().await;
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        assert!(notifications.lock().unwrap().is_empty());
        tick(24 * 60 * 60 - 1).await;
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        tick(1).await;
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert!(notifications.lock().unwrap().is_empty());
        tick(24 * 60 * 60).await;
        assert_eq!(checks.load(Ordering::SeqCst), 3);
        assert_eq!(*notifications.lock().unwrap(), ["1.2.3"]);
        online.send_replace(false);
        tick(24 * 60 * 60).await;
        assert_eq!(checks.load(Ordering::SeqCst), 3);
        online.send_replace(true);
        tokio::task::yield_now().await;
        assert_eq!(checks.load(Ordering::SeqCst), 4);
        assert_eq!(*notifications.lock().unwrap(), ["1.2.3"]);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn canceling_lifecycle_drops_in_flight_check_and_all_timers() {
        struct PendingCheck(Arc<AtomicBool>);
        impl Drop for PendingCheck {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let (_online, receiver) = watch::channel(true);
        let started = Arc::new(AtomicUsize::new(0));
        let checks = started.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let check_dropped = dropped.clone();
        let task = tokio::spawn(schedule(
            Duration::from_secs(24 * 60 * 60),
            receiver,
            move || {
                checks.fetch_add(1, Ordering::SeqCst);
                let guard = PendingCheck(check_dropped.clone());
                async move {
                    let _guard = guard;
                    std::future::pending::<Result<Option<String>, ()>>().await
                }
            },
            |_| panic!("unfinished checks cannot notify"),
        ));
        tokio::task::yield_now().await;
        tick(60).await;
        assert_eq!(started.load(Ordering::SeqCst), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(dropped.load(Ordering::SeqCst));
        tick(48 * 60 * 60).await;
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }
}
