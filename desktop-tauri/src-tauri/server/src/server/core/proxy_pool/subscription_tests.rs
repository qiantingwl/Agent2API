use super::*;
use std::collections::HashSet;

#[test]
fn subscription_lifecycle_preserves_manual_proxy_and_stable_references() {
    crate::test_support::isolated(concat!(module_path!(), "::subscription_lifecycle_preserves_manual_proxy_and_stable_references"), || {
        let db = Db::open(&crate::paths::config_dir().join("proxy-test.db")).unwrap();
        install(Some(db.clone()));
        crate::server::core::proxy_settings::install(Some(db.clone()));
        let settings = crate::server::core::proxy_settings::save(&json!({"listenerPortBase":20100,"listenerPortEnd":20200})).unwrap();
        assert_eq!(settings["listenerPortBase"], 20100);
        assert!(crate::server::core::proxy_settings::save(&json!({"listenerPortEnd":100})).is_err());
        assert_eq!(crate::server::core::proxy_settings::get(), settings, "非法区间不能部分落库");
        crate::server::core::subscriptions::install(Some(db.clone()));
        create(&json!({"name":"manual", "host":"127.0.0.1", "port":19080, "nonDirect":true})).unwrap();
        let manual = list()[0].clone();
        let manual_id = manual["id"].as_str().unwrap();
        assert!(resolve_reference(manual_id).unwrap().non_direct);

        let subscriptions = crate::server::core::subscriptions::create(&json!({
            "name":"local fixture", "kind":"local",
            "content":"proxies:\n  - name: fixture\n    type: http\n    server: 127.0.0.1\n    port: 19080\n"
        })).unwrap();
        let provider_id = subscriptions[0]["id"].as_str().unwrap().to_string();
        crate::server::config::init(Some(db.clone()));
        let kernel_dir = crate::paths::config_dir().join("proxy-kernel").to_string_lossy().into_owned();
        assert!(crate::server::config::set_kernel_dir(Some(kernel_dir.clone())));
        assert!(crate::server::config::set_kernel_proxy(Some(json!({"source":"pool","proxyId":manual_id}))));
        assert_eq!(crate::server::config::kernel_dir_raw(), Some(kernel_dir.clone()));
        assert!(usage::referenced_pool_ids(None).contains(manual_id));
        let stored: String = db.with(|conn| conn.query_row("SELECT value FROM kv WHERE key='kernelDir'", [], |row| row.get(0)).unwrap()).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), json!(kernel_dir));
        assert!(crate::server::core::subscriptions::live_ids().unwrap().contains(&provider_id), "保存配置不能清除订阅保留键");
        let mut target = SubscriptionNodeTarget { provider_id, sub_name:"local fixture".into(), node:"fixture".into(), port:None };
        assert_eq!(sync_subscription_nodes(&[target_clone(&target)]).unwrap(), 1);
        let node = list().into_iter().find(|item| item["source"] == "subscription").unwrap();
        let id = node["id"].as_str().unwrap().to_string();
        assert!(resolve_reference(&id).unwrap_err().contains("监听端口尚未就绪"));
        assert!(listener_node_keys(&HashSet::new()).is_empty());
        let references = HashSet::from([id.as_str()]);
        assert!(needs_listener(&id, &references));

        target.port = Some(19081);
        sync_subscription_nodes(&[target_clone(&target)]).unwrap();
        assert_eq!(resolve_reference(&id).unwrap().port, Some(19081));
        assert!(!resolve_reference(&id).unwrap().non_direct);
        assert_eq!(sync_subscription_nodes(&[target_clone(&target)]).unwrap(), 0);
        assert!(update(&json!({"id":id,"name":"overwrite"})).is_err());
        assert!(remove(&id).is_err());
        set_enabled(&id, false).unwrap();
        assert!(resolve_reference(&id).unwrap_err().contains("已禁用"));
        assert!(resolve_for_test(&id).is_ok());
        assert!(listener_node_keys(&references).is_empty());
        target.port = Some(19082);
        sync_subscription_nodes(&[target_clone(&target)]).unwrap();
        assert!(resolve_reference(&id).is_err(), "同步不能重新启用本地禁用的节点");
        set_enabled(&id, true).unwrap();
        assert_eq!(resolve_reference(&id).unwrap().port, Some(19082));
        assert_eq!(unprovision_subscription_nodes().unwrap(), 1);
        assert!(resolve_reference(&id).is_err());
        assert!(needs_listener(&id, &references));
        sync_subscription_nodes(&[target_clone(&target)]).unwrap();
        assert!(resolve_reference(&id).is_ok(), "重装内核后沿用节点引用");
        let mut replacement = target_clone(&target);
        replacement.node = "replacement".into();
        sync_subscription_nodes(&[replacement]).unwrap();
        assert!(resolve_reference(&id).is_err(), "消失节点不能继续使用旧端口");
        sync_subscription_nodes(&[target_clone(&target)]).unwrap();
        assert!(resolve_reference(&id).is_ok(), "节点再次出现时恢复原引用");
        assert_eq!(prune_orphan_subscription_items(&HashSet::new()).unwrap(), 2);
        assert!(resolve_reference(&id).is_err());
        assert_eq!(list(), vec![manual], "订阅增删不能改变手动代理及其非直连配置");
    });
}

fn target_clone(value: &SubscriptionNodeTarget) -> SubscriptionNodeTarget {
    SubscriptionNodeTarget {
        provider_id: value.provider_id.clone(), sub_name: value.sub_name.clone(),
        node: value.node.clone(), port: value.port,
    }
}
