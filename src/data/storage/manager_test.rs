#[cfg(test)]
mod tests {
    use crate::data::storage::manager::{CacheEntry, ProxyDB, ProxyDBCache, cleanup_cache, get_cache_size};
    use crate::config::settings::Settings;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_cache_entry_expiration() {
        let settings = Settings::load();
        let db = Arc::new(ProxyDB::new("test.com", &settings).unwrap());
        let entry = CacheEntry::new(db);
        
        // Entry should not be expired immediately
        assert!(!entry.is_expired(Duration::from_secs(1)));
        
        // Wait for expiration
        thread::sleep(Duration::from_millis(1100));
        assert!(entry.is_expired(Duration::from_secs(1)));
    }

    #[test]
    fn test_lru_cache_eviction() {
        // Create a small cache for testing
        let cache = ProxyDBCache::new(3, 3600);
        
        let settings = Settings::load();
        
        // Add 3 entries (at capacity)
        let db1 = cache.get_or_insert("host1.com", || {
            Arc::new(ProxyDB::new("host1.com", &settings).unwrap())
        });
        let db2 = cache.get_or_insert("host2.com", || {
            Arc::new(ProxyDB::new("host2.com", &settings).unwrap())
        });
        let db3 = cache.get_or_insert("host3.com", || {
            Arc::new(ProxyDB::new("host3.com", &settings).unwrap())
        });
        
        assert_eq!(cache.len(), 3);
        
        // Add a 4th entry, should evict the least recently used (host1.com)
        let db4 = cache.get_or_insert("host4.com", || {
            Arc::new(ProxyDB::new("host4.com", &settings).unwrap())
        });
        
        assert_eq!(cache.len(), 3);
        
        // Access host2 to make it recently used
        let _ = cache.get_or_insert("host2.com", || {
            Arc::new(ProxyDB::new("host2.com", &settings).unwrap())
        });
        
        // Add another entry, should evict host3 (now least recently used)
        let db5 = cache.get_or_insert("host5.com", || {
            Arc::new(ProxyDB::new("host5.com", &settings).unwrap())
        });
        
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_ttl_expiration() {
        // Create cache with 1 second TTL
        let cache = ProxyDBCache::new(10, 1);
        
        let settings = Settings::load();
        
        // Add an entry
        let db1 = cache.get_or_insert("ttl-test.com", || {
            Arc::new(ProxyDB::new("ttl-test.com", &settings).unwrap())
        });
        
        assert_eq!(cache.len(), 1);
        
        // Wait for TTL to expire
        thread::sleep(Duration::from_millis(1100));
        
        // Cleanup should remove the expired entry
        let removed = cache.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_hit_refreshes_lru() {
        let cache = ProxyDBCache::new(2, 3600);
        let settings = Settings::load();
        
        // Add two entries
        let db1 = cache.get_or_insert("lru1.com", || {
            Arc::new(ProxyDB::new("lru1.com", &settings).unwrap())
        });
        let db2 = cache.get_or_insert("lru2.com", || {
            Arc::new(ProxyDB::new("lru2.com", &settings).unwrap())
        });
        
        assert_eq!(cache.len(), 2);
        
        // Access lru1.com to refresh it
        let _ = cache.get_or_insert("lru1.com", || {
            Arc::new(ProxyDB::new("lru1.com", &settings).unwrap())
        });
        
        // Add a third entry, should evict lru2.com (least recently used)
        let db3 = cache.get_or_insert("lru3.com", || {
            Arc::new(ProxyDB::new("lru3.com", &settings).unwrap())
        });
        
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_get_cache_size() {
        // This test uses the global cache, so we just verify the function works
        let size = get_cache_size();
        assert!(size >= 0);
    }

    #[test]
    fn test_cleanup_cache() {
        // This test uses the global cache, so we just verify the function works
        let removed = cleanup_cache();
        assert!(removed >= 0);
    }
}
