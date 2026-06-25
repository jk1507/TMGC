"""
Fix lr_model.pkl pickle class reference.
The model was pickled while train_real_data.py was __main__, so pickle
stored the class as __main__.ScaledModelWrapper. We need to reassign
it to ml_ensemble.ScaledModelWrapper so ml_ensemble.py can load it.
"""
import pickle
import sys
import ml_ensemble

# Define ScaledModelWrapper in __main__ namespace so pickle can find it
sys.modules['__main__'].ScaledModelWrapper = ml_ensemble.ScaledModelWrapper

# Load the model
with open('lr_model.pkl', 'rb') as f:
    model = pickle.load(f)

print(f'[OK] LR model loaded successfully')
print(f'  Class: {model.__class__}')
print(f'  Module: {model.__class__.__module__}')

# Update class reference to ml_ensemble
model.__class__ = ml_ensemble.ScaledModelWrapper
print(f'  Updated class module to: {model.__class__.__module__}')

# Re-save with correct class reference
with open('lr_model.pkl', 'wb') as f:
    pickle.dump(model, f)
print(f'[OK] LR model re-saved with correct class reference')
