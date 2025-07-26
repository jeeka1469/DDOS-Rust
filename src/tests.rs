#[cfg(test)]
mod tests {
    use crate::{FlowFeatures, DDoSError};
    use crate::ddos_detector::DDoSDetector;

    #[test]
    fn test_ddos_detector_creation() {
        let _detector = DDoSDetector::new(60, 100);
        // We can't access private fields, so we'll just test that it doesn't panic
        assert!(true);
    }

    #[test]
    fn test_flow_features_default() {
        let features = FlowFeatures::default();
        assert_eq!(features.protocol, 0);
        assert_eq!(features.src_port, 0);
        assert_eq!(features.dst_port, 0);
        assert_eq!(features.tot_fwd_pkts, 0);
        assert_eq!(features.tot_bwd_pkts, 0);
    }

    #[test]
    fn test_flow_features_creation() {
        let mut features = FlowFeatures::default();
        features.src_ip = "192.168.1.1".to_string();
        features.dst_ip = "192.168.1.2".to_string();
        features.protocol = 6; // TCP
        
        assert_eq!(features.src_ip, "192.168.1.1");
        assert_eq!(features.dst_ip, "192.168.1.2");
        assert_eq!(features.protocol, 6);
    }

    #[test]
    fn test_ddos_detector_threshold_check() {
        let mut detector = DDoSDetector::new(60, 2); // Low threshold for testing
        
        // First request should not trigger alert
        let result1 = detector.check_ip("192.168.1.100", "TEST");
        assert!(result1.is_none());
        
        // Second request should trigger alert (reaches threshold of 2)
        let result2 = detector.check_ip("192.168.1.100", "TEST");
        assert!(result2.is_some());
        
        // Third request should also trigger alert
        let result3 = detector.check_ip("192.168.1.100", "TEST");
        assert!(result3.is_some());
        
        if let Some(alert) = result3 {
            assert!(alert.contains("192.168.1.100"));
            assert!(alert.contains("TEST"));
        }
    }

    #[test]
    fn test_error_types() {
        let io_error = DDoSError::IoError("Test IO error".to_string());
        let model_error = DDoSError::ModelError("Test model error".to_string());
        let config_error = DDoSError::ConfigError("Test config error".to_string());
        
        assert!(format!("{}", io_error).contains("IO error"));
        assert!(format!("{}", model_error).contains("Model error"));
        assert!(format!("{}", config_error).contains("Configuration error"));
    }

    #[test]
    fn test_error_from_str() {
        let error: DDoSError = "Test error message".into();
        match error {
            DDoSError::ConfigError(msg) => assert_eq!(msg, "Test error message"),
            _ => panic!("Expected ConfigError"),
        }
    }
}
