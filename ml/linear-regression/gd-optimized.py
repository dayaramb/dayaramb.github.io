import numpy as np

# --- Data and Hyperparameters ---
# Convert lists to NumPy arrays for vectorized operations
x_values = np.array([3.5, 3.69, 3.44, 3.43, 4.34, 4.42, 2.37])
y_values = np.array([18, 15, 18, 16, 15, 14, 24])
alpha = 0.01

# --- Vectorized Functions ---

# The predict function is no longer needed, as 'm * x + b' is simpler.

def calculate_loss_and_gradients(m, b, x, y):
    """
    Calculates the loss and gradients in a single, efficient pass.
    """
    # 1. Make predictions for all x_values at once
    predictions = m * x + b
    
    # 2. Calculate the error (y - y_hat) once and reuse it
    error = y - predictions
    
    # 3. Calculate Mean Squared Error (Loss)
    loss = np.mean(error**2)
    
    # 4. Calculate gradients using the pre-calculated error
    weight_gradient = -2 * np.mean(x * error)
    bias_gradient = -2 * np.mean(error)
    
    return loss, weight_gradient, bias_gradient

def main():
    m = 0.0
    b = 0.0
    
    print(f"{'Iteration':<12} | {'Weight':<10} | {'Bias':<10} | {'Loss'}")
    print("-" * 50)

    for i in range(2000000):
        # Calculate everything needed for this iteration in one go
        loss, w_grad, b_grad = calculate_loss_and_gradients(m, b, x_values, y_values)
        
        # Print the state *before* the update
        print(f"{i:<12} | {m:<10.4f} | {b:<10.4f} | {loss:.4f}")
        
        # Update the parameters
        m = m - alpha * w_grad
        b = b - alpha * b_grad

main()