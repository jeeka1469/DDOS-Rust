use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;
use crate::FlowFeatures;

pub struct ModelPredictor {
    model: PyObject,
    scaler: PyObject,
    feature_columns: Vec<String>,
}

impl ModelPredictor {
    pub fn new(model_path: &str, scaler_path: &str, metadata_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Python::with_gil(|py| {
            // Import required modules
            let joblib = py.import("joblib")?;
            let numpy = py.import("numpy")?;
            let pandas = py.import("pandas")?;

            // Load model, scaler, and metadata
            let model = joblib.call_method1("load", (model_path,))?.into();
            let scaler = joblib.call_method1("load", (scaler_path,))?.into();
            let metadata = joblib.call_method1("load", (metadata_path,))?;

            // Extract feature columns from metadata
            let feature_columns: Vec<String> = metadata
                .get_item("feature_columns")?
                .extract()?;

            Ok(ModelPredictor {
                model,
                scaler,
                feature_columns,
            })
        })
    }
    
    pub fn predict(&self, features: &FlowFeatures) -> Result<(String, f64), Box<dyn std::error::Error>> {
        Python::with_gil(|py| {
            // Convert FlowFeatures to Python dict
            let feature_dict = self.features_to_dict(features)?;
            
            // Create pandas DataFrame
            let pandas = py.import("pandas")?;
            let df = pandas.call_method1("DataFrame", ([feature_dict],))?;
            
            // Ensure columns match training data
            use pyo3::types::IntoPyDict;
            let kwargs = [("columns", self.feature_columns.clone())].into_py_dict(py)?;
            
            // Print real-time packet info
            println!("\n\x1b[36m=== New Packet Detected ===\x1b[0m");
            println!("Source IP: \x1b[33m{}\x1b[0m", features.src_ip);
            println!("Destination IP: \x1b[33m{}\x1b[0m", features.dst_ip);
            println!("Protocol: \x1b[33m{}\x1b[0m", features.protocol);
            let df = df.call_method("reindex", (), Some(&kwargs))?;
            
            // Scale features
            let scaled_features = self.scaler.call_method1(py, "transform", (df,))?;

            // Make prediction
            let scaled_features_for_pred = scaled_features.call_method0(py, "copy")?;
            let prediction = self.model.call_method1(py, "predict", (scaled_features_for_pred,))?;
            let prediction_proba = self.model.call_method1(py, "predict_proba", (scaled_features,))?;
            
            // Extract results - handle numpy array outputs
            let pred_array: Vec<String> = prediction.extract(py)?;
            let pred_class = pred_array.get(0)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let probabilities: Vec<Vec<f64>> = prediction_proba.extract(py)?;
            let confidence = probabilities[0].iter().fold(0.0_f64, |a, &b| a.max(b));
            
            Ok((pred_class, confidence))
        })
    }
    
    fn features_to_dict(&self, features: &FlowFeatures) -> Result<PyObject, Box<dyn std::error::Error>> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            
            // Add all numeric features
            dict.set_item("flow_duration", features.flow_duration)?;
            dict.set_item("flow_byts_s", features.flow_byts_s)?;
            dict.set_item("flow_pkts_s", features.flow_pkts_s)?;
            dict.set_item("fwd_pkts_s", features.fwd_pkts_s)?;
            dict.set_item("bwd_pkts_s", features.bwd_pkts_s)?;
            dict.set_item("tot_fwd_pkts", features.tot_fwd_pkts)?;
            dict.set_item("tot_bwd_pkts", features.tot_bwd_pkts)?;
            dict.set_item("totlen_fwd_pkts", features.totlen_fwd_pkts)?;
            dict.set_item("totlen_bwd_pkts", features.totlen_bwd_pkts)?;
            dict.set_item("fwd_pkt_len_max", features.fwd_pkt_len_max)?;
            dict.set_item("fwd_pkt_len_min", features.fwd_pkt_len_min)?;
            dict.set_item("fwd_pkt_len_mean", features.fwd_pkt_len_mean)?;
            dict.set_item("fwd_pkt_len_std", features.fwd_pkt_len_std)?;
            dict.set_item("bwd_pkt_len_max", features.bwd_pkt_len_max)?;
            dict.set_item("bwd_pkt_len_min", features.bwd_pkt_len_min)?;
            dict.set_item("bwd_pkt_len_mean", features.bwd_pkt_len_mean)?;
            dict.set_item("bwd_pkt_len_std", features.bwd_pkt_len_std)?;
            dict.set_item("pkt_len_max", features.pkt_len_max)?;
            dict.set_item("pkt_len_min", features.pkt_len_min)?;
            dict.set_item("pkt_len_mean", features.pkt_len_mean)?;
            dict.set_item("pkt_len_std", features.pkt_len_std)?;
            dict.set_item("pkt_len_var", features.pkt_len_var)?;
            dict.set_item("flow_iat_mean", features.flow_iat_mean)?;
            dict.set_item("flow_iat_max", features.flow_iat_max)?;
            dict.set_item("flow_iat_min", features.flow_iat_min)?;
            dict.set_item("flow_iat_std", features.flow_iat_std)?;
            dict.set_item("fwd_iat_tot", features.fwd_iat_tot)?;
            dict.set_item("fwd_iat_max", features.fwd_iat_max)?;
            dict.set_item("fwd_iat_min", features.fwd_iat_min)?;
            dict.set_item("fwd_iat_mean", features.fwd_iat_mean)?;
            dict.set_item("fwd_iat_std", features.fwd_iat_std)?;
            dict.set_item("bwd_iat_tot", features.bwd_iat_tot)?;
            dict.set_item("bwd_iat_max", features.bwd_iat_max)?;
            dict.set_item("bwd_iat_min", features.bwd_iat_min)?;
            dict.set_item("bwd_iat_mean", features.bwd_iat_mean)?;
            dict.set_item("bwd_iat_std", features.bwd_iat_std)?;
            dict.set_item("fin_flag_cnt", features.fin_flag_cnt)?;
            dict.set_item("syn_flag_cnt", features.syn_flag_cnt)?;
            dict.set_item("rst_flag_cnt", features.rst_flag_cnt)?;
            dict.set_item("psh_flag_cnt", features.psh_flag_cnt)?;
            dict.set_item("ack_flag_cnt", features.ack_flag_cnt)?;
            dict.set_item("urg_flag_cnt", features.urg_flag_cnt)?;
            dict.set_item("down_up_ratio", features.down_up_ratio)?;
            dict.set_item("pkt_size_avg", features.pkt_size_avg)?;
            dict.set_item("init_fwd_win_byts", features.init_fwd_win_byts)?;
            dict.set_item("init_bwd_win_byts", features.init_bwd_win_byts)?;
            
            // Handle categorical features (IP addresses, protocol)
            dict.set_item("protocol", features.protocol)?;
            dict.set_item("src_ip", features.src_ip.clone())?;
            dict.set_item("dst_ip", features.dst_ip.clone())?;
            dict.set_item("src_port", features.src_port)?;
            dict.set_item("dst_port", features.dst_port)?;
            
            Ok(dict.into())
        })
    }
}

// Helper function to apply label encoders (if needed)
pub fn apply_label_encoders(features: &mut FlowFeatures, metadata_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    Python::with_gil(|py| {
        let joblib = py.import("joblib")?;
        let metadata = joblib.call_method1("load", (metadata_path,))?;
        let label_encoders: HashMap<String, PyObject> = metadata
            .get_item("label_encoders")?
            .extract()?;
        
        // Apply encoders to categorical features
        // Protocol is already a number (e.g., 6 for TCP, 17 for UDP)
        // No need to encode it as it's already in the correct format
        if let Some(src_ip_encoder) = label_encoders.get("src_ip") {
            let encoded = src_ip_encoder.call_method1(py, "transform", ([&features.src_ip],));
            match encoded {
                Ok(val) => {
                    let arr: Vec<i64> = val.extract(py)?;
                    let val = arr.get(0).copied().unwrap_or(-1);
                    features.src_ip = val.to_string();
                },
                Err(_) => {
                    features.src_ip = "-1".to_string();
                }
            }
        }
        if let Some(dst_ip_encoder) = label_encoders.get("dst_ip") {
            let encoded = dst_ip_encoder.call_method1(py, "transform", ([&features.dst_ip],));
            match encoded {
                Ok(val) => {
                    let arr: Vec<i64> = val.extract(py)?;
                    let val = arr.get(0).copied().unwrap_or(-1);
                    features.dst_ip = val.to_string();
                },
                Err(_) => {
                    features.dst_ip = "-1".to_string();
                }
            }
        }

        // Enforce integer encoding for src_ip, dst_ip
        // Protocol is already i64, no need to parse
        if features.src_ip.parse::<i64>().is_err() {
            features.src_ip = "-1".to_string();
        }
        if features.dst_ip.parse::<i64>().is_err() {
            features.dst_ip = "-1".to_string();
        }

        Ok(())
    })
}