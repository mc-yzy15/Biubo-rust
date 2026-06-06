use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PatchStatus {
    Pending,
    Reviewed,
    Applied,
    Ignored,
}

impl std::fmt::Display for PatchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchStatus::Pending => write!(f, "pending"),
            PatchStatus::Reviewed => write!(f, "reviewed"),
            PatchStatus::Applied => write!(f, "applied"),
            PatchStatus::Ignored => write!(f, "ignored"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchSuggestion {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub rule_id: Option<String>,
    pub patch_content: String,
    pub status: PatchStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePatchRequest {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub rule_id: Option<String>,
    pub patch_content: String,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePatchStatusRequest {
    pub status: PatchStatus,
}

#[derive(Debug)]
pub struct PatchStorage {
    patches: RwLock<HashMap<String, PatchSuggestion>>,
}

impl PatchStorage {
    pub fn new() -> Self {
        PatchStorage {
            patches: RwLock::new(HashMap::new()),
        }
    }

    pub fn list_patches(&self, status_filter: Option<&PatchStatus>) -> Vec<PatchSuggestion> {
        let patches = self.patches.read();
        let mut result: Vec<PatchSuggestion> = patches
            .values()
            .map(|p| p.clone())
            .collect();

        if let Some(status) = status_filter {
            result.retain(|p| p.status == *status);
        }

        result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        result
    }

    pub fn get_patch(&self, id: &str) -> Option<PatchSuggestion> {
        let patches = self.patches.read();
        patches.get(id).map(|p| p.clone())
    }

    pub fn create_patch(&self, request: CreatePatchRequest) -> PatchSuggestion {
        let id = format!("patch_{}", uuid::Uuid::new_v4().to_string()[..8].to_string());
        let now = Utc::now();

        let patch = PatchSuggestion {
            id: id.clone(),
            title: request.title,
            description: request.description,
            severity: request.severity,
            rule_id: request.rule_id,
            patch_content: request.patch_content,
            status: PatchStatus::Pending,
            created_at: now,
            updated_at: None,
            metadata: request.metadata,
        };

        let mut patches = self.patches.write();
        patches.insert(id, patch.clone());
        patch
    }

    pub fn update_status(&self, id: &str, status: PatchStatus) -> Option<PatchSuggestion> {
        let mut patches = self.patches.write();
        if let Some(patch) = patches.get_mut(id) {
            patch.status = status;
            patch.updated_at = Some(Utc::now());
            Some(patch.clone())
        } else {
            None
        }
    }

    pub fn delete_patch(&self, id: &str) -> bool {
        let mut patches = self.patches.write();
        patches.remove(id).is_some()
    }

    pub fn count(&self) -> usize {
        self.patches.read().len()
    }
}

impl Default for PatchStorage {
    fn default() -> Self {
        Self::new()
    }
}

pub type SharedPatchStorage = Arc<PatchStorage>;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_patch_request() -> CreatePatchRequest {
        CreatePatchRequest {
            title: "Test Patch".to_string(),
            description: "A test patch".to_string(),
            severity: "high".to_string(),
            rule_id: Some("rule-001".to_string()),
            patch_content: "PATCH_CONTENT".to_string(),
            metadata: None,
        }
    }

    #[test]
    fn test_create_patch() {
        let storage = PatchStorage::new();
        let request = create_test_patch_request();
        let patch = storage.create_patch(request);

        assert!(patch.id.starts_with("patch_"));
        assert_eq!(patch.title, "Test Patch");
        assert_eq!(patch.status, PatchStatus::Pending);
        assert_eq!(storage.count(), 1);
    }

    #[test]
    fn test_get_patch() {
        let storage = PatchStorage::new();
        let request = create_test_patch_request();
        let created = storage.create_patch(request);

        let retrieved = storage.get_patch(&created.id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, created.id);
    }

    #[test]
    fn test_get_patch_not_found() {
        let storage = PatchStorage::new();
        let result = storage.get_patch("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_list_patches_no_filter() {
        let storage = PatchStorage::new();
        storage.create_patch(create_test_patch_request());

        let patches = storage.list_patches(None);
        assert_eq!(patches.len(), 1);
    }

    #[test]
    fn test_list_patches_with_filter() {
        let storage = PatchStorage::new();
        storage.create_patch(create_test_patch_request());

        let pending = storage.list_patches(Some(&PatchStatus::Pending));
        assert_eq!(pending.len(), 1);

        let applied = storage.list_patches(Some(&PatchStatus::Applied));
        assert_eq!(applied.len(), 0);
    }

    #[test]
    fn test_update_status() {
        let storage = PatchStorage::new();
        let created = storage.create_patch(create_test_patch_request());

        let updated = storage.update_status(&created.id, PatchStatus::Reviewed);
        assert!(updated.is_some());
        assert_eq!(updated.unwrap().status, PatchStatus::Reviewed);
        assert!(updated.unwrap().updated_at.is_some());
    }

    #[test]
    fn test_update_status_not_found() {
        let storage = PatchStorage::new();
        let result = storage.update_status("nonexistent", PatchStatus::Reviewed);
        assert!(result.is_none());
    }

    #[test]
    fn test_delete_patch() {
        let storage = PatchStorage::new();
        let created = storage.create_patch(create_test_patch_request());

        let deleted = storage.delete_patch(&created.id);
        assert!(deleted);
        assert_eq!(storage.count(), 0);
        assert!(storage.get_patch(&created.id).is_none());
    }

    #[test]
    fn test_delete_patch_not_found() {
        let storage = PatchStorage::new();
        let result = storage.delete_patch("nonexistent");
        assert!(!result);
    }

    #[test]
    fn test_patch_status_display() {
        assert_eq!(PatchStatus::Pending.to_string(), "pending");
        assert_eq!(PatchStatus::Reviewed.to_string(), "reviewed");
        assert_eq!(PatchStatus::Applied.to_string(), "applied");
        assert_eq!(PatchStatus::Ignored.to_string(), "ignored");
    }

    #[test]
    fn test_multiple_patches_sorted_by_date() {
        let storage = PatchStorage::new();

        storage.create_patch(CreatePatchRequest {
            title: "Patch A".to_string(),
            description: "A".to_string(),
            severity: "low".to_string(),
            rule_id: None,
            patch_content: "A".to_string(),
            metadata: None,
        });

        storage.create_patch(CreatePatchRequest {
            title: "Patch B".to_string(),
            description: "B".to_string(),
            severity: "medium".to_string(),
            rule_id: None,
            patch_content: "B".to_string(),
            metadata: None,
        });

        let patches = storage.list_patches(None);
        assert_eq!(patches.len(), 2);
        assert_eq!(patches[0].title, "Patch B");
    }

    #[test]
    fn test_patch_with_metadata() {
        let storage = PatchStorage::new();
        let mut metadata = HashMap::new();
        metadata.insert("source".to_string(), serde_json::json!("auto_detection"));

        let request = CreatePatchRequest {
            title: "Metadata Patch".to_string(),
            description: "With metadata".to_string(),
            severity: "critical".to_string(),
            rule_id: None,
            patch_content: "CONTENT".to_string(),
            metadata: Some(metadata),
        };

        let patch = storage.create_patch(request);
        assert!(patch.metadata.is_some());
        assert_eq!(
            patch.metadata.unwrap().get("source").unwrap().as_str().unwrap(),
            "auto_detection"
        );
    }
}
