use log::{info, warn};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;

use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client};

#[derive(Clone, Debug)]
pub struct PodMetadata {
    pub pod_name: String,
    pub namespace: String,
    pub labels: BTreeMap<String, String>,
    pub service_account: String,
}

pub fn resolve_pod_metadata(
    container_id: &str,
    cache: &HashMap<String, PodMetadata>,
) -> Option<PodMetadata> {
    if container_id.is_empty() {
        return None;
    }
    // Try exact match first, then prefix match (short IDs)
    if let Some(meta) = cache.get(container_id) {
        return Some(meta.clone());
    }
    for (key, meta) in cache {
        if key.starts_with(container_id) || container_id.starts_with(key) {
            return Some(meta.clone());
        }
    }
    None
}

pub async fn start_pod_watcher(cache: Arc<RwLock<HashMap<String, PodMetadata>>>) {
    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "Kubernetes API not available, pod enrichment disabled: {}",
                e
            );
            return;
        }
    };

    info!("Kubernetes pod watcher started");

    loop {
        match poll_pods(&client).await {
            Ok(new_cache) => {
                let count = new_cache.len();
                *cache.write().await = new_cache;
                info!("Refreshed {} container→pod mappings", count);
            }
            Err(e) => {
                warn!("Failed to list pods: {}", e);
            }
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

async fn poll_pods(client: &Client) -> Result<HashMap<String, PodMetadata>, kube::Error> {
    let pods: Api<Pod> = Api::all(client.clone());
    let pod_list = pods.list(&Default::default()).await?;

    let mut map = HashMap::new();

    for pod in pod_list {
        let metadata = pod.metadata;
        let pod_name = metadata.name.unwrap_or_default();
        let namespace = metadata.namespace.unwrap_or_default();
        let labels = metadata.labels.unwrap_or_default();

        let service_account = pod
            .spec
            .as_ref()
            .and_then(|s| s.service_account_name.clone())
            .unwrap_or_default();

        let pod_meta = PodMetadata {
            pod_name,
            namespace,
            labels,
            service_account,
        };

        // Extract container IDs from status
        if let Some(status) = pod.status {
            let all_statuses = status
                .container_statuses
                .into_iter()
                .flatten()
                .chain(status.init_container_statuses.into_iter().flatten());

            for cs in all_statuses {
                if let Some(cid) = cs.container_id {
                    // Format: "containerd://abc123..." or "docker://abc123..."
                    let short_id = cid
                        .rsplit("://")
                        .next()
                        .unwrap_or(&cid)
                        .get(..12)
                        .unwrap_or(&cid);
                    map.insert(short_id.to_string(), pod_meta.clone());
                }
            }
        }
    }

    Ok(map)
}
