use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;
use crate::FlowFeatures;

pub struct ModelPredictor {
    model: PyObject,
    scaler: PyObject,
    feature_columns: Vec<String>,
    #[allow(dead_code)]
    label_encoders: HashMap<String, PyObject>,
    #[allow(dead_code)]
    column_mappings: HashMap<String, String>,
}

impl ModelPredictor {
    pub fn new(model_path: &str, scaler_path: &str, metadata_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Python::with_gil(|py| {

            let joblib = py.import("joblib")?;

            let model = joblib.call_method1("load", (model_path,))?.into();
            let scaler = joblib.call_method1("load", (scaler_path,))?.into();
            let metadata = joblib.call_method1("load", (metadata_path,))?;

            let feature_columns: Vec<String> = metadata
                .get_item("feature_columns")?
                .extract()?;

            let label_encoders_py = metadata.get_item("label_encoders")?;
            let mut label_encoders = HashMap::new();

            if let Ok(label_encoders_dict) = label_encoders_py.downcast::<PyDict>() {
                for (key, value) in label_encoders_dict.iter() {
                    let key_str: String = key.extract()?;
                    label_encoders.insert(key_str, value.into());
                }
            }

            let mut column_mappings = HashMap::new();
            if let Ok(mappings_py) = metadata.get_item("column_mappings") {
                if let Ok(mappings_dict) = mappings_py.downcast::<PyDict>() {
                    for (key, value) in mappings_dict.iter() {
                        let key_str: String = key.extract()?;
                        let value_str: String = value.extract()?;
                        column_mappings.insert(key_str, value_str);
                    }
                }
            }

            Ok(ModelPredictor {
                model,
                scaler,
                feature_columns,
                label_encoders,
                column_mappings,
            })
        })
    }

    #[allow(dead_code)]
    pub fn predict(&self, features: &FlowFeatures) -> Result<(String, f64), Box<dyn std::error::Error>> {
        self.predict_with_display(features, &features.src_ip, &features.dst_ip)
    }

    pub fn predict_with_display(&self, features: &FlowFeatures, orig_src_ip: &str, orig_dst_ip: &str) -> Result<(String, f64), Box<dyn std::error::Error>> {
        Python::with_gil(|py| {

            let mut enhanced_features = features.clone();

            self.create_engineered_features(&mut enhanced_features);

            let feature_dict = self.features_to_dict(&enhanced_features)?;

            let pandas = py.import("pandas")?;
            let df = pandas.call_method1("DataFrame", ([feature_dict],))?;

            use pyo3::types::IntoPyDict;
            let kwargs = [("columns", self.feature_columns.clone())].into_py_dict(py)?;

            println!("\n\x1b[36m=== New Packet Detected ===\x1b[0m");
            println!("Source IP: \x1b[33m{}\x1b[0m", orig_src_ip);
            println!("Destination IP: \x1b[33m{}\x1b[0m", orig_dst_ip);
            println!("Protocol: \x1b[33m{}\x1b[0m", features.protocol);
            let df = df.call_method("reindex", (), Some(&kwargs))?;

            let scaled_features = self.scaler.call_method1(py, "transform", (df,))?;

            let scaled_features_for_pred = scaled_features.call_method0(py, "copy")?;
            let prediction = self.model.call_method1(py, "predict", (scaled_features_for_pred,))?;
            let prediction_proba = self.model.call_method1(py, "predict_proba", (scaled_features,))?;

            let pred_array: Vec<String> = prediction.extract(py)?;
            let pred_class = pred_array.get(0)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let probabilities: Vec<Vec<f64>> = prediction_proba.extract(py)?;
            let confidence = probabilities[0].iter().fold(0.0_f64, |a, &b| a.max(b));

            Ok((pred_class, confidence))
        })
    }

    fn create_engineered_features(&self, features: &mut FlowFeatures) {

        features.fwd_bwd_ratio = if features.tot_bwd_pkts > 0 {
            features.tot_fwd_pkts as f64 / features.tot_bwd_pkts as f64
        } else {
            features.tot_fwd_pkts as f64
        };

        features.avg_fwd_pkt_size = if features.tot_fwd_pkts > 0 {
            features.totlen_fwd_pkts as f64 / features.tot_fwd_pkts as f64
        } else {
            0.0
        };

        let total_packets = features.tot_fwd_pkts + features.tot_bwd_pkts;
        let total_bytes = features.totlen_fwd_pkts + features.totlen_bwd_pkts;
        features.flow_efficiency = if total_packets > 0 {
            total_bytes as f64 / total_packets as f64
        } else {
            0.0
        };

        features.total_flags = features.fin_flag_cnt as u32 +
                              features.syn_flag_cnt as u32 +
                              features.rst_flag_cnt as u32 +
                              features.psh_flag_cnt as u32 +
                              features.ack_flag_cnt as u32 +
                              features.urg_flag_cnt as u32 +
                              features.ece_flag_cnt as u32 +
                              features.cwr_flag_count as u32;

        let flags = vec![
            features.fin_flag_cnt, features.syn_flag_cnt, features.rst_flag_cnt,
            features.psh_flag_cnt, features.ack_flag_cnt, features.urg_flag_cnt,
            features.ece_flag_cnt, features.cwr_flag_count
        ];
        features.flag_diversity = flags.iter().filter(|&&x| x > 0).count() as f64;

        features.is_tcp = if features.protocol == 6 { 1 } else { 0 };
        features.is_udp = if features.protocol == 17 { 1 } else { 0 };
        features.is_icmp = if features.protocol == 1 { 1 } else { 0 };

        features.src_is_wellknown = if features.src_port <= 1023 { 1 } else { 0 };
        features.dst_is_wellknown = if features.dst_port <= 1023 { 1 } else { 0 };

        let common_ports = vec![20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 139, 143, 161, 194, 443, 993, 995];
        features.src_is_common = if common_ports.contains(&features.src_port) { 1 } else { 0 };
        features.dst_is_common = if common_ports.contains(&features.dst_port) { 1 } else { 0 };
    }

    fn features_to_dict(&self, features: &FlowFeatures) -> Result<PyObject, Box<dyn std::error::Error>> {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);

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

            dict.set_item("fwd_bwd_ratio", features.fwd_bwd_ratio)?;
            dict.set_item("avg_fwd_pkt_size", features.avg_fwd_pkt_size)?;
            dict.set_item("flow_efficiency", features.flow_efficiency)?;
            dict.set_item("total_flags", features.total_flags)?;
            dict.set_item("flag_diversity", features.flag_diversity)?;
            dict.set_item("is_tcp", features.is_tcp)?;
            dict.set_item("is_udp", features.is_udp)?;
            dict.set_item("is_icmp", features.is_icmp)?;
            dict.set_item("src_is_wellknown", features.src_is_wellknown)?;
            dict.set_item("dst_is_wellknown", features.dst_is_wellknown)?;
            dict.set_item("src_is_common", features.src_is_common)?;
            dict.set_item("dst_is_common", features.dst_is_common)?;

            dict.set_item("protocol", features.protocol)?;
            dict.set_item("src_ip", features.src_ip.clone())?;
            dict.set_item("dst_ip", features.dst_ip.clone())?;
            dict.set_item("src_port", features.src_port)?;
            dict.set_item("dst_port", features.dst_port)?;

            Ok(dict.into())
        })
    }
}

pub fn apply_label_encoders(features: &mut FlowFeatures, metadata_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    Python::with_gil(|py| {
        let joblib = py.import("joblib")?;
        let metadata = joblib.call_method1("load", (metadata_path,))?;
        let label_encoders: HashMap<String, PyObject> = metadata
            .get_item("label_encoders")?
            .extract()?;

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

        if features.src_ip.parse::<i64>().is_err() {
            features.src_ip = "-1".to_string();
        }
        if features.dst_ip.parse::<i64>().is_err() {
            features.dst_ip = "-1".to_string();
        }

        Ok(())
    })
}
