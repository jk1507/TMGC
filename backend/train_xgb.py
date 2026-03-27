from ml_model import generate_training_data
from ml_xgboost import train_xgb

# Generate synthetic data (temporary)
X, y = generate_training_data(3000)

train_xgb(X, y)