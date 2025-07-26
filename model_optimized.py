import numpy as np
import pandas as pd
import os
import glob
import gc
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler, MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif, RFE
from sklearn.decomposition import PCA
from sklearn.pipeline import Pipeline
from sklearn.utils.class_weight import compute_class_weight

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from xgboost import XGBClassifier
from sklearn.neural_network import MLPClassifier

import joblib
import warnings
warnings.filterwarnings('ignore')

pd.set_option('mode.copy_on_write', True)

class OptimizedDDoSAnalysis:
    def __init__(self, dataset_dir, max_samples_per_file=75000):
        self.dataset_dir = dataset_dir
        self.csv_files = [f for f in os.listdir(dataset_dir) if f.endswith('.csv')]
        self.max_samples_per_file = max_samples_per_file
        self.unified_data = None
        self.scaler = None
        self.best_model = None
        self.feature_columns = None
        self.label_encoders = {}
        self.original_network_data = {}
        self.feature_selector = None
        self.pca = None
        
        # Enhanced column mappings with more variations
        self.column_mappings = {
            'Flow Packets/s': 'flow_pkts_s',
            'Packet Length Mean': 'pkt_len_mean',
            'Flow IAT Mean': 'flow_iat_mean',
            'SYN Flag Count': 'syn_flag_cnt',
            'ACK Flag Count': 'ack_flag_cnt',
            'RST Flag Count': 'rst_flag_cnt',
            'FIN Flag Count': 'fin_flag_cnt',
            'Flow Duration': 'flow_duration',
            'Flow Bytes/s': 'flow_byts_s',
            'Down/Up Ratio': 'down_up_ratio',
            'Fwd Packets/s': 'fwd_pkts_s',
            'Bwd Packets/s': 'bwd_pkts_s',
            'Flow IAT Std': 'flow_iat_std',
            'Source IP': 'src_ip',
            'Protocol': 'protocol',
            'Label': 'label',
            'Timestamp': 'timestamp',
            # Additional mappings for common variations
            'Total Fwd Packets': 'tot_fwd_pkts',
            'Total Backward Packets': 'tot_bwd_pkts',
            'Total Length of Fwd Packets': 'totlen_fwd_pkts',
            'Total Length of Bwd Packets': 'totlen_bwd_pkts',
            'Fwd Packet Length Max': 'fwd_pkt_len_max',
            'Fwd Packet Length Min': 'fwd_pkt_len_min',
            'Fwd Packet Length Mean': 'fwd_pkt_len_mean',
            'Fwd Packet Length Std': 'fwd_pkt_len_std',
            'Bwd Packet Length Max': 'bwd_pkt_len_max',
            'Bwd Packet Length Min': 'bwd_pkt_len_min',
            'Bwd Packet Length Mean': 'bwd_pkt_len_mean',
            'Bwd Packet Length Std': 'bwd_pkt_len_std',
            'Packet Length Max': 'pkt_len_max',
            'Packet Length Min': 'pkt_len_min',
            'Packet Length Std': 'pkt_len_std',
            'Packet Length Variance': 'pkt_len_var',
            'FIN Flag Count': 'fin_flag_cnt',
            'SYN Flag Count': 'syn_flag_cnt',
            'RST Flag Count': 'rst_flag_cnt',
            'PSH Flag Count': 'psh_flag_cnt',
            'ACK Flag Count': 'ack_flag_cnt',
            'URG Flag Count': 'urg_flag_cnt',
            'CWE Flag Count': 'cwr_flag_count',
            'ECE Flag Count': 'ece_flag_cnt',
            'Init_Win_bytes_forward': 'init_fwd_win_byts',
            'Init_Win_bytes_backward': 'init_bwd_win_byts',
            'act_data_pkt_fwd': 'fwd_act_data_pkts',
            'min_seg_size_forward': 'fwd_seg_size_min',
            'Active Mean': 'active_mean',
            'Active Std': 'active_std',
            'Active Max': 'active_max',
            'Active Min': 'active_min',
            'Idle Mean': 'idle_mean',
            'Idle Std': 'idle_std',
            'Idle Max': 'idle_max',
            'Idle Min': 'idle_min',
            # Direct mappings
            'src_ip': 'src_ip', 'dst_ip': 'dst_ip',
            'src_port': 'src_port', 'dst_port': 'dst_port',
            'protocol': 'protocol', 'timestamp': 'timestamp',
            'flow_duration': 'flow_duration', 'flow_byts_s': 'flow_byts_s',
            'flow_pkts_s': 'flow_pkts_s', 'fwd_pkts_s': 'fwd_pkts_s',
            'bwd_pkts_s': 'bwd_pkts_s', 'pkt_len_mean': 'pkt_len_mean',
            'flow_iat_mean': 'flow_iat_mean', 'flow_iat_std': 'flow_iat_std',
            'fin_flag_cnt': 'fin_flag_cnt', 'syn_flag_cnt': 'syn_flag_cnt',
            'rst_flag_cnt': 'rst_flag_cnt', 'ack_flag_cnt': 'ack_flag_cnt',
            'down_up_ratio': 'down_up_ratio', 'label': 'label'
        }

    def normalize_column_names(self, df):
        """Enhanced column normalization with better pattern matching"""
        # Strip whitespace and handle common variations
        df.columns = df.columns.str.strip().str.replace(' ', '_').str.lower()
        
        # Apply mappings
        current_mapping = {}
        for col in df.columns:
            # Direct mapping
            if col in self.column_mappings:
                current_mapping[col] = self.column_mappings[col]
            # Pattern-based mapping for variations
            elif 'source' in col and 'ip' in col:
                current_mapping[col] = 'src_ip'
            elif 'destination' in col and 'ip' in col:
                current_mapping[col] = 'dst_ip'
            elif 'source' in col and 'port' in col:
                current_mapping[col] = 'src_port'
            elif 'destination' in col and 'port' in col:
                current_mapping[col] = 'dst_port'
            elif col in ['class', 'attack', 'type']:
                current_mapping[col] = 'label'
        
        return df.rename(columns=current_mapping)

    def create_engineered_features(self, df):
        """Create additional engineered features for better accuracy"""
        print("- Creating engineered features...")
        
        # Ratio features
        if 'tot_fwd_pkts' in df.columns and 'tot_bwd_pkts' in df.columns:
            df['fwd_bwd_ratio'] = df['tot_fwd_pkts'] / (df['tot_bwd_pkts'] + 1)
            df['bwd_fwd_ratio'] = df['tot_bwd_pkts'] / (df['tot_fwd_pkts'] + 1)
        
        # Packet size features
        if 'totlen_fwd_pkts' in df.columns and 'tot_fwd_pkts' in df.columns:
            df['avg_fwd_pkt_size'] = df['totlen_fwd_pkts'] / (df['tot_fwd_pkts'] + 1)
        if 'totlen_bwd_pkts' in df.columns and 'tot_bwd_pkts' in df.columns:
            df['avg_bwd_pkt_size'] = df['totlen_bwd_pkts'] / (df['tot_bwd_pkts'] + 1)
        
        # Flow efficiency features
        if 'flow_duration' in df.columns and 'flow_pkts_s' in df.columns:
            df['flow_efficiency'] = df['flow_pkts_s'] * df['flow_duration']
        
        # Flag combinations (attack patterns)
        flag_cols = ['fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt', 'urg_flag_cnt']
        available_flags = [col for col in flag_cols if col in df.columns]
        if len(available_flags) >= 2:
            df['total_flags'] = df[available_flags].sum(axis=1)
            df['flag_diversity'] = (df[available_flags] > 0).sum(axis=1)
        
        # Protocol-specific features
        if 'protocol' in df.columns:
            df['is_tcp'] = (df['protocol'] == 6).astype(int)
            df['is_udp'] = (df['protocol'] == 17).astype(int)
            df['is_icmp'] = (df['protocol'] == 1).astype(int)
        
        # Port-based features
        if 'src_port' in df.columns and 'dst_port' in df.columns:
            # Well-known ports
            df['src_is_wellknown'] = (df['src_port'] <= 1024).astype(int)
            df['dst_is_wellknown'] = (df['dst_port'] <= 1024).astype(int)
            # Common service ports
            common_ports = [80, 443, 22, 21, 25, 53, 110, 995, 993, 143]
            df['src_is_common'] = df['src_port'].isin(common_ports).astype(int)
            df['dst_is_common'] = df['dst_port'].isin(common_ports).astype(int)
        
        print(f"✓ Created {len([col for col in df.columns if col not in self.original_network_data]) - len(self.original_network_data)} new features")
        return df

    def load_all_datasets(self, target_column='label'):
        """Enhanced dataset loading with better sampling"""
        all_dataframes = []
        print("\nStarting to load datasets...")
        print(f"Found {len(self.csv_files)} CSV files in directory")
        
        # Track label distribution across files
        label_distribution = Counter()
        
        for csv_file in self.csv_files:
            file_path = os.path.join(self.dataset_dir, csv_file)
            print(f"\nProcessing file: {csv_file}")
            try:
                print(f"- Loading {csv_file}...")
                df = pd.read_csv(file_path, low_memory=False)
                print(f"- Normalizing column names for {csv_file}...")
                df = self.normalize_column_names(df)
                
                # Find label column
                if target_column not in df.columns:
                    print(f"- Looking for alternative label column in {csv_file}...")
                    for alt in ['Label', 'label', 'LABEL', 'target', 'Target', 'class', 'Class', 'attack', 'Attack']:
                        if alt in df.columns:
                            df.rename(columns={alt: target_column}, inplace=True)
                            print(f"  - Found and renamed column '{alt}' to '{target_column}'")
                            break
                    else:
                        print(f"  - No suitable label column found in {csv_file}, skipping...")
                        continue
                
                # Clean and standardize labels
                df[target_column] = df[target_column].astype(str).str.strip().str.upper()
                label_distribution.update(df[target_column].value_counts().to_dict())
                
                # Enhanced sampling strategy - balanced per class
                if len(df) > self.max_samples_per_file:
                    print(f"- Applying balanced sampling to {csv_file} (original size: {len(df)} rows)")
                    samples_per_class = self.max_samples_per_file // df[target_column].nunique()
                    df = df.groupby(target_column, group_keys=False).apply(
                        lambda x: x.sample(min(len(x), samples_per_class), random_state=42)
                    ).reset_index(drop=True)
                    print(f"  - Reduced to {len(df)} rows with balanced sampling")
                
                df['source_file'] = csv_file.replace('.csv', '')
                all_dataframes.append(df)
                print(f"✓ Successfully processed {csv_file}")
                
            except Exception as e:
                print(f"❌ Error loading {csv_file}: {e}")
                continue
        
        if not all_dataframes:
            return None
        
        combined_df = pd.concat(all_dataframes, ignore_index=True)
        print(f"\n📊 Combined dataset statistics:")
        print(f"- Total samples: {len(combined_df)}")
        print(f"- Label distribution:")
        for label, count in combined_df[target_column].value_counts().items():
            print(f"  {label}: {count} ({count/len(combined_df)*100:.1f}%)")
        
        return combined_df

    def preprocess_unified_data(self, df, target_column='label'):
        """Enhanced preprocessing with feature engineering"""
        print("\nStarting enhanced data preprocessing...")
        
        print("1. Storing original network identifiers...")
        self.original_network_data = {
            'src_ip': df['src_ip'].copy() if 'src_ip' in df.columns else None,
            'dst_ip': df['dst_ip'].copy() if 'dst_ip' in df.columns else None,
            'protocol': df['protocol'].copy() if 'protocol' in df.columns else None,
            'src_port': df['src_port'].copy() if 'src_port' in df.columns else None,
            'dst_port': df['dst_port'].copy() if 'dst_port' in df.columns else None
        }
        print("✓ Network identifiers stored")

        print("\n2. Feature engineering...")
        df = self.create_engineered_features(df)

        print("\n3. Cleaning dataset...")
        df.drop(['source_file'], axis=1, errors='ignore', inplace=True)
        df.drop([col for col in ['timestamp', 'Timestamp'] if col in df.columns], axis=1, inplace=True)
        df.drop([col for col in df.columns if 'Unnamed' in col], axis=1, inplace=True)
        print("✓ Unnecessary columns removed")

        if target_column not in df.columns:
            print("❌ Error: Target column not found in dataset")
            return None, None, None, None

        print("\n4. Label preprocessing...")
        # Standardize attack labels to match your Rust model expectations
        label_mapping = {
            'BENIGN': 'BENIGN',
            'NORMAL': 'BENIGN',
            'DNS': 'DNS',
            'NTP': 'NTP', 
            'HTTP': 'HTTP',
            'LDAP': 'LDAP',
            'MSSQL': 'MSSQL',
            'NETBIOS': 'NetBIOS',
            'NETBIOS_NAME_SERVICE': 'NetBIOS',
            'PORTMAP': 'Portmap',
            'RECURSIVE_GET': 'RECURSIVE_GET',
            'SLOWLORIS': 'SLOWLORIS',
            'SLOW_POST': 'SLOW_POST',
            'SYN': 'SYN',
            'UDP': 'UDP',
            'UDPLAG': 'UDPLag',
            'DDOS': 'UDP',  # Generic DDoS -> UDP
            'ATTACK': 'UDP',  # Generic attack -> UDP
            'FLOOD': 'UDP'   # Generic flood -> UDP
        }
        
        # Apply label mapping
        df[target_column] = df[target_column].map(label_mapping).fillna(df[target_column])
        print(f"✓ Standardized labels: {sorted(df[target_column].unique())}")

        print("\n5. Preparing features...")
        available_features = [col for col in df.columns if col != target_column]
        print(f"- Found {len(available_features)} features to process")

        # Enhanced categorical encoding
        print("- Encoding categorical features...")
        encoded_count = 0
        for col in df[available_features].select_dtypes(include='object').columns:
            if col not in ['src_ip', 'dst_ip']:  # Keep these as strings for network analysis
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                self.label_encoders[col] = le
                encoded_count += 1
        print(f"✓ Encoded {encoded_count} categorical columns")

        print("\n6. Preparing features and target variables...")
        X = df[available_features]
        y = df[target_column]
        
        # Convert to numeric, handling any remaining non-numeric data
        numeric_cols = X.select_dtypes(exclude='object').columns
        X = X[numeric_cols].astype(np.float32)
        
        self.feature_columns = list(X.columns)
        print(f"- Features shape: {X.shape}")
        print(f"- Target shape: {y.shape}")

        print("\n7. Advanced data cleaning...")
        # Handle missing values
        print("- Handling missing values...")
        X = X.fillna(X.median())
        
        # Handle infinite values
        print("- Handling infinite values...")
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(X.median())
        
        # Remove constant features
        print("- Removing constant features...")
        constant_features = X.columns[X.std() == 0]
        if len(constant_features) > 0:
            X = X.drop(columns=constant_features)
            self.feature_columns = list(X.columns)
            print(f"  - Removed {len(constant_features)} constant features")
        
        # Outlier detection and handling
        print("- Handling outliers...")
        Q1 = X.quantile(0.25)
        Q3 = X.quantile(0.75)
        IQR = Q3 - Q1
        lower_bound = Q1 - 3 * IQR
        upper_bound = Q3 + 3 * IQR
        X = X.clip(lower=lower_bound, upper=upper_bound, axis=1)
        print("✓ Advanced data cleaning complete")

        # Stratified split with better handling of imbalanced classes
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
        except ValueError:
            # If stratification fails due to class imbalance, use regular split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )

        print(f"✓ Data split complete:")
        print(f"  - Training: {X_train.shape[0]} samples")
        print(f"  - Testing: {X_test.shape[0]} samples")
        
        return X_train, X_test, y_train, y_test

    def scale_features(self, X_train, X_test, method='robust'):
        """Enhanced feature scaling with multiple options"""
        print(f"\nScaling features using {method} scaler...")
        
        if method == 'robust':
            self.scaler = RobustScaler()
        elif method == 'minmax':
            self.scaler = MinMaxScaler()
        else:
            self.scaler = StandardScaler()
        
        print("- Fitting and transforming training data...")
        X_train_scaled = self.scaler.fit_transform(X_train).astype(np.float32)
        
        print("- Transforming test data...")
        X_test_scaled = self.scaler.transform(X_test).astype(np.float32)
        
        print(f"✓ Scaling complete using {method} scaler")
        return X_train_scaled, X_test_scaled

    def feature_selection(self, X_train, X_test, y_train, method='mutual_info', k=50):
        """Advanced feature selection"""
        print(f"\nPerforming feature selection using {method}...")
        
        if method == 'mutual_info':
            selector = SelectKBest(score_func=mutual_info_classif, k=min(k, X_train.shape[1]))
        elif method == 'f_classif':
            selector = SelectKBest(score_func=f_classif, k=min(k, X_train.shape[1]))
        elif method == 'rfe':
            estimator = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
            selector = RFE(estimator, n_features_to_select=min(k, X_train.shape[1]))
        else:
            return X_train, X_test  # No selection
        
        X_train_selected = selector.fit_transform(X_train, y_train)
        X_test_selected = selector.transform(X_test)
        
        self.feature_selector = selector
        
        if hasattr(selector, 'get_support'):
            selected_features = [self.feature_columns[i] for i in range(len(self.feature_columns)) 
                               if selector.get_support()[i]]
            print(f"✓ Selected {len(selected_features)} most informative features")
            print(f"  Top features: {selected_features[:10]}")
        
        return X_train_selected, X_test_selected

    def train_best_model(self, X_train, X_test, y_train, y_test):
        """Enhanced model training with ensemble methods"""
        print("\nStarting enhanced model training...")
        
        # Calculate class weights for imbalanced data
        class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
        class_weight_dict = dict(zip(np.unique(y_train), class_weights))
        
        print("Initializing enhanced models for training:")
        models = {
            'Optimized Random Forest': {
                'model': RandomForestClassifier(
                    random_state=42, 
                    n_jobs=-1,
                    class_weight='balanced'
                ),
                'params': {
                    'n_estimators': [200, 300, 500],
                    'max_depth': [15, 20, 25, None],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2, 4],
                    'max_features': ['sqrt', 'log2', None],
                    'bootstrap': [True, False]
                }
            },
            'XGBoost': {
                'model': XGBClassifier(
                    random_state=42,
                    n_jobs=-1,
                    eval_metric='mlogloss'
                ),
                'params': {
                    'n_estimators': [200, 300],
                    'max_depth': [6, 8, 10],
                    'learning_rate': [0.01, 0.1, 0.2],
                    'subsample': [0.8, 0.9, 1.0],
                    'colsample_bytree': [0.8, 0.9, 1.0]
                }
            },
            'Gradient Boosting': {
                'model': GradientBoostingClassifier(random_state=42),
                'params': {
                    'n_estimators': [200, 300],
                    'max_depth': [5, 7, 9],
                    'learning_rate': [0.01, 0.1, 0.2],
                    'subsample': [0.8, 0.9, 1.0]
                }
            },
            'Extra Trees': {
                'model': ExtraTreesClassifier(
                    random_state=42, 
                    n_jobs=-1,
                    class_weight='balanced'
                ),
                'params': {
                    'n_estimators': [200, 300],
                    'max_depth': [15, 20, None],
                    'min_samples_split': [2, 5],
                    'min_samples_leaf': [1, 2]
                }
            }
        }

        # Add neural network for larger datasets
        if X_train.shape[0] > 10000:
            models['Neural Network'] = {
                'model': MLPClassifier(random_state=42, max_iter=500),
                'params': {
                    'hidden_layer_sizes': [(100,), (200,), (100, 50), (200, 100)],
                    'alpha': [0.0001, 0.001, 0.01],
                    'learning_rate': ['constant', 'adaptive']
                }
            }

        # Add SVM for smaller datasets
        if X_train.shape[0] < 50000:
            models['Optimized SVM'] = {
                'model': SVC(random_state=42, class_weight='balanced'),
                'params': {
                    'C': [0.1, 1, 10, 100],
                    'kernel': ['rbf', 'linear', 'poly'],
                    'gamma': ['scale', 'auto', 0.001, 0.01]
                }
            }

        best_model, best_score, best_model_name = None, 0, ""
        results = {}
        
        # Use stratified k-fold for better evaluation
        cv_strategy = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

        for name, setup in models.items():
            try:
                print(f"\nTraining {name}...")
                print(f"- Starting Grid Search CV with Stratified K-Fold...")
                
                grid = GridSearchCV(
                    setup['model'], 
                    setup['params'], 
                    scoring='f1_weighted',
                    cv=cv_strategy, 
                    n_jobs=-1, 
                    verbose=1
                )
                
                print(f"- Fitting model...")
                grid.fit(X_train, y_train)
                
                print(f"- Making predictions...")
                y_pred = grid.best_estimator_.predict(X_test)
                acc = accuracy_score(y_test, y_pred)
                f1 = f1_score(y_test, y_pred, average='weighted')
                
                print(f"✓ {name} training complete")
                print(f"  - Accuracy: {acc:.4f}")
                print(f"  - F1-Score: {f1:.4f}")
                print(f"  - Best CV Score: {grid.best_score_:.4f}")

                results[name] = {
                    'model': grid.best_estimator_,
                    'best_params': grid.best_params_,
                    'best_cv_score': grid.best_score_,
                    'test_accuracy': acc,
                    'test_f1': f1,
                    'classification_report': classification_report(y_test, y_pred),
                    'confusion_matrix': confusion_matrix(y_test, y_pred)
                }
                
                # Use F1 score for model selection (better for imbalanced data)
                if f1 > best_score:
                    best_score, best_model, best_model_name = f1, grid.best_estimator_, name
                    
            except Exception as e:
                print(f"❌ Error training {name}: {e}")
            
            gc.collect()

        # Create ensemble of top 3 models
        if len(results) >= 3:
            print(f"\nCreating ensemble model...")
            top_models = sorted(results.items(), key=lambda x: x[1]['test_f1'], reverse=True)[:3]
            
            voting_models = [(name.replace(' ', '_'), result['model']) for name, result in top_models]
            ensemble = VotingClassifier(estimators=voting_models, voting='soft')
            
            print(f"- Training ensemble of: {[name for name, _ in top_models]}")
            ensemble.fit(X_train, y_train)
            
            y_pred_ensemble = ensemble.predict(X_test)
            acc_ensemble = accuracy_score(y_test, y_pred_ensemble)
            f1_ensemble = f1_score(y_test, y_pred_ensemble, average='weighted')
            
            print(f"✓ Ensemble complete")
            print(f"  - Accuracy: {acc_ensemble:.4f}")
            print(f"  - F1-Score: {f1_ensemble:.4f}")
            
            results['Ensemble'] = {
                'model': ensemble,
                'best_params': 'N/A',
                'best_cv_score': 'N/A',
                'test_accuracy': acc_ensemble,
                'test_f1': f1_ensemble,
                'classification_report': classification_report(y_test, y_pred_ensemble),
                'confusion_matrix': confusion_matrix(y_test, y_pred_ensemble)
            }
            
            if f1_ensemble > best_score:
                best_score, best_model, best_model_name = f1_ensemble, ensemble, 'Ensemble'

        self.best_model = best_model
        return results, best_model, best_model_name, best_score

    def save_model_and_scaler(self, model_name="unified_ddos_best_model"):
        """Enhanced model saving with all components"""
        if self.best_model and self.scaler:
            joblib.dump(self.best_model, f"{model_name}.pkl")
            joblib.dump(self.scaler, f"{model_name}_scaler.pkl")
            
            metadata = {
                'feature_columns': self.feature_columns,
                'label_encoders': self.label_encoders,
                'original_network_data': self.original_network_data,
                'column_mappings': self.column_mappings,
                'feature_selector': self.feature_selector,
                'pca': self.pca if hasattr(self, 'pca') else None
            }
            joblib.dump(metadata, f"{model_name}_metadata.pkl")
            
            print(f"✓ Model saved as: {model_name}.pkl")
            print(f"✓ Scaler saved as: {model_name}_scaler.pkl")
            print(f"✓ Metadata saved as: {model_name}_metadata.pkl")
            
            return f"{model_name}.pkl", f"{model_name}_scaler.pkl", f"{model_name}_metadata.pkl"
        return None, None, None

    def load_model_and_scaler(self, model_name="unified_ddos_best_model"):
        """Enhanced model loading"""
        try:
            self.best_model = joblib.load(f"{model_name}.pkl")
            self.scaler = joblib.load(f"{model_name}_scaler.pkl")
            metadata = joblib.load(f"{model_name}_metadata.pkl")
            
            self.feature_columns = metadata['feature_columns']
            self.label_encoders = metadata['label_encoders']
            self.original_network_data = metadata.get('original_network_data', {})
            self.feature_selector = metadata.get('feature_selector', None)
            self.pca = metadata.get('pca', None)
            
            print(f"✓ Successfully loaded model: {model_name}")
            return True
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return False

    def predict_with_confidence(self, X):
        """Enhanced prediction with confidence scores"""
        if hasattr(self.best_model, 'predict_proba'):
            probabilities = self.best_model.predict_proba(X)
            predictions = self.best_model.predict(X)
            confidences = np.max(probabilities, axis=1)
            return predictions, confidences
        else:
            predictions = self.best_model.predict(X)
            # For models without probability, use distance-based confidence
            confidences = np.ones(len(predictions)) * 0.8  # Default confidence
            return predictions, confidences


if __name__ == '__main__':
    dataset_dir = 'C:/Users/jeeka/DDOS_AI/03-11/'
    analyzer = OptimizedDDoSAnalysis(dataset_dir, max_samples_per_file=75000)

    print("🚀 OPTIMIZED DDOS ANALYSIS PIPELINE")
    print("=" * 60)
    
    print("LOADING DATASETS\n" + "=" * 60)
    combined_df = analyzer.load_all_datasets()

    if combined_df is not None:
        print("PREPROCESSING DATA\n" + "=" * 60)
        X_train, X_test, y_train, y_test = analyzer.preprocess_unified_data(combined_df)
        
        if X_train is not None:
            print("SCALING FEATURES\n" + "=" * 60)
            X_train_scaled, X_test_scaled = analyzer.scale_features(X_train, X_test, method='robust')

            print("FEATURE SELECTION\n" + "=" * 60)
            X_train_selected, X_test_selected = analyzer.feature_selection(
                X_train_scaled, X_test_scaled, y_train, method='mutual_info', k=50
            )

            print("TRAINING ENHANCED MODELS\n" + "=" * 60)
            results, best_model, best_model_name, best_score = analyzer.train_best_model(
                X_train_selected, X_test_selected, y_train, y_test
            )

            print("SAVING OPTIMIZED MODEL\n" + "=" * 60)
            model_file, scaler_file, metadata_file = analyzer.save_model_and_scaler("unified_ddos_best_model")

            print("\n🎯 FINAL RESULTS")
            print("=" * 60)
            print(f"Best Model: {best_model_name}")
            print(f"Best F1-Score: {best_score:.4f}")
            
            if best_model_name in results:
                result = results[best_model_name]
                print(f"Test Accuracy: {result['test_accuracy']:.4f}")
                print(f"Test F1-Score: {result['test_f1']:.4f}")
                
                print("\n📊 Classification Report:")
                print(result['classification_report'])
                
                if hasattr(best_model, 'feature_importances_'):
                    if analyzer.feature_selector and hasattr(analyzer.feature_selector, 'get_support'):
                        selected_features = [analyzer.feature_columns[i] for i in range(len(analyzer.feature_columns)) 
                                           if analyzer.feature_selector.get_support()[i]]
                    else:
                        selected_features = analyzer.feature_columns
                    
                    importance_df = pd.DataFrame({
                        'feature': selected_features,
                        'importance': best_model.feature_importances_
                    }).sort_values('importance', ascending=False)
                    
                    print("\n🔝 Top 15 Most Important Features:")
                    print(importance_df.head(15).to_string(index=False))

            # Model comparison
            print(f"\n📈 MODEL COMPARISON:")
            print("-" * 60)
            for name, result in results.items():
                print(f"{name:<25} | Acc: {result['test_accuracy']:.4f} | F1: {result['test_f1']:.4f}")
            
            print(f"\n✅ Optimized model saved successfully!")
            print(f"   - Model: {model_file}")
            print(f"   - Scaler: {scaler_file}")
            print(f"   - Metadata: {metadata_file}")
            
    else:
        print("❌ Failed to load datasets")
