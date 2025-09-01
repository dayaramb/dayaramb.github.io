# Linear Regression 📈

Linear regression is a simple statistical technique used to find the relationship between variables. It finds the relationship between features and a label.

---

## Variables in Linear Regression

In any linear regression model, the variables are split into two categories: what you know (X) and what you want to predict (Y).

### **X Variable: The Input**

The **X variable** represents the input or the information you are using to make a prediction. It's the cause in a cause-and-effect relationship.

Other common names for the X variable include:
* **Features**
* Explanatory Variable
* Independent Variable
* Predictor Variable
* Input Variable

---

### **Y Variable: The Output**

The **Y variable** is what you are trying to predict. Its value is dependent on the X variable(s). It's the effect in a cause-and-effect relationship.

Other common names for the Y variable include:
* **Label**
* Outcome Variable
* Dependent Variable
* Target Variable
* Response Variable



## Linear regression equation"

In algebric terms, the model is defiend as:
$$y= mx + b$$


## Model Parameters: Weights and Bias

To create the relationship between X and Y, the model learns two types of parameters:

### **Weights (Slope)**

A **weight** is a number that represents the importance of each input feature (X). It's like the **slope** of a line—it determines how much a change in an input feature affects the output prediction (Y).

### **Bias (Y-Intercept)**

The **bias** is a single number that acts as a baseline for predictions. It's like the **y-intercept** of a line, allowing the model to shift its output up or down to better fit the data, even when all input features are zero.

![Mathematical representation of a simple linear model](./bias-weight.png)



## Models with multiple Features:

$$Y' = b + w_1x_1 + w_2x_2 + w_3x_3 + w_4x_4 + w_5 x_5$$

During training the bias and weight of the linear regression equation are updated.


## Linear Regression Loss:

Loss is a numerical metric that describes how wrong a model's prediction is. Loss measures the distance between the model's predicitons and the actual lables. The goal of the training a model is to minimize the loss,



---

## Loss Functions: Measuring Model Error 📏

A loss function calculates the difference (or error) between the model's prediction and the actual value. The goal of training is to minimize this loss.

### **MAE (L1 Loss) - Mean Absolute Error**

**MAE** measures the average absolute difference between the actual and predicted values.

* **Formula**:
    $$
    MAE = \frac{1}{n} \sum_{i=1}^{n} |y_i - \hat{y}_i|
    $$
* **Key Characteristic**: MAE is **robust to outliers** because it does not square the errors. A few large errors will not dominate the total loss.

### **MSE (L2 Loss) - Mean Squared Error**

**MSE** measures the average of the squared differences between the actual and predicted values.

* **Formula**:
    $$
    MSE = \frac{1}{n} \sum_{i=1}^{n} (y_i - \hat{y}_i)^2
    $$
* **Key Characteristic**: MSE is **sensitive to outliers**. It penalizes larger errors much more heavily, making it a good choice when you want to avoid large mistakes.



## Gradient Descent:

Gradient descent is a mathematical technique used to find the weights and bias that produce the model with the lowest loss.

Example of calulating Gradient Descent:
Ref: https://developers.google.com/machine-learning/crash-course/linear-regression/gradient-descent#expandable-1

# Car Weight vs. Fuel Efficiency Dataset 🚗

This is a small, simple dataset that shows the relationship between a car's weight and its fuel efficiency. It can be used for basic linear regression exercises.

---

## The Data

The dataset consists of two variables: the car's weight in thousands of pounds (the feature) and its fuel efficiency in miles per gallon (the label).

| Weight (1000s of lbs) | Miles Per Gallon (MPG) |
| :-------------------- | :--------------------- |
| 3.50                  | 18                     |
| 3.69                  | 15                     |
| 3.44                  | 18                     |
| 3.43                  | 16                     |
| 4.34                  | 15                     |
| 4.42                  | 14                     |
| 2.37                  | 24                     |

---

## Variable Definitions

* **Feature (Input):** `Pounds in 1000s`
    * This is the independent variable used to make a prediction.

* **Label (Output):** `Miles per gallon`
    * This is the dependent variable that we are trying to predict.



## Gradient Descent Calculation:

In each iteration, we perform two main operations:

Calculate the Gradients: We determine the direction of steepest ascent for the loss function with respect to both the weight and the bias.

Update Parameters: We adjust the weight and bias in the opposite direction of their gradients, scaled by the learning rate, to minimize the error.




Derivatiion:

# Gradient Derivation for Linear Regression

This document outlines the mathematical derivation of the gradients for the weight (slope) and bias (intercept) parameters in simple linear regression using the Mean Squared Error (MSE) loss function.

---

## The Loss Function: MSE

First, we define our loss function, **J(m, b)**, as the **Mean Squared Error (MSE)**. This function measures the average squared difference between the actual values ($y_i$) and the predicted values ($\hat{y}_i$).

$$
J(m,b) = \frac{1}{n} \sum_{i=1}^{n} (y_i - \hat{y}_i)^2
$$

Since the predicted value $\hat{y}_i$ is given by the line equation `mx_i + b`, we can write the loss function as:

$$
J(m,b) = \frac{1}{n} \sum_{i=1}^{n} (y_i - (mx_i + b))^2
$$

---

## Gradients

The **gradient** tells us the direction of the steepest increase of the loss function. To minimize the loss, we calculate the partial derivative of the loss function with respect to each parameter (`m` and `b`) and move in the opposite direction.

### Derivation of the Gradient for the Weight (m)

To find the gradient for the weight, we compute the partial derivative of `J` with respect to `m`.

1.  **Start with the Loss Function:**
   $$
    \frac{\partial J}{\partial m} = \frac{\partial}{\partial m} \left[ \frac{1}{n} \sum_{i=1}^{n} (y_i - (mx_i + b))^2 \right]
   $$
2.  **Apply the Chain Rule:**
    * **Outer function**: $u^2$, where $u = y_i - (mx_i + b)$. The derivative is $2u$.
    * **Inner function**: $y_i - (mx_i + b)$. The derivative with respect to `m` is $-x_i$.

3.  **Combine and Simplify:**
    $$
    \frac{\partial J}{\partial m} = \frac{1}{n} \sum_{i=1}^{n} 2 \cdot (y_i - (mx_i + b)) \cdot (-x_i)
    $$
    This gives us the final formula for the "weight slope":
    $$
    \frac{\partial J}{\partial m} = -\frac{2}{n} \sum_{i=1}^{n} x_i(y_i - \hat{y}_i)
    $$

### Derivation of the Gradient for the Bias (b)

Similarly, to find the gradient for the bias, we compute the partial derivative of `J` with respect to `b`.

1.  **Start with the Loss Function:**
    $$
    \frac{\partial J}{\partial b} = \frac{\partial}{\partial b} \left[ \frac{1}{n} \sum_{i=1}^{n} (y_i - (mx_i + b))^2 \right]
    $$

2.  **Apply the Chain Rule:**
    * **Outer function**: $u^2$, where $u = y_i - (mx_i + b)$. The derivative is $2u$.
    * **Inner function**: $y_i - (mx_i + b)$. The derivative with respect to `b` is $-1$.

3.  **Combine and Simplify:**
   $$
    \frac{\partial J}{\partial b} = \frac{1}{n} \sum_{i=1}^{n} 2 \cdot (y_i - (mx_i + b)) \cdot (-1)
   $$

   This gives us the final formula for the "bias slope":
   $$
    \frac{\partial J}{\partial b} = -\frac{2}{n} \sum_{i=1}^{n} (y_i - \hat{y}_i)
   $$
> *Note: Some libraries remove the `2` from the gradient formula.*

New Weight = Old Weight - (Learning Rate * Weight Slope)

New Bias = Old Bias - (Learning Rate * Bias Slope)


So, for the first

Of course. For the first iteration with the weight (**w**) and bias (**b**) set to 0, the Mean Squared Error (MSE) is approximately **303.71**.

Here are the steps for the calculation.

---
## Iteration 1
---
### 1. Calculate the Predicted Values ($\hat{y}$)
The formula for the predicted value is $\hat{y} = wx + b$. Since you set $w=0$ and $b=0$, the predicted value for every car's MPG will be 0, regardless of its weight.

$$\hat{y} = (0 \cdot x) + 0 = 0$$

### 2. Calculate the Squared Error for Each Data Point
Next, we calculate the squared difference between the actual MPG ($y$) and the predicted MPG ($\hat{y}$) for each car. The formula is $(y - \hat{y})^2$.

| Weight (x) | Actual MPG (y) | Predicted MPG ($\hat{y}$) | Squared Error $(y - \hat{y})^2$ |
| :--- | :--- | :--- | :--- |
| 3.50 | 18 | 0 | $(18 - 0)^2 = 324$ |
| 3.69 | 15 | 0 | $(15 - 0)^2 = 225$ |
| 3.44 | 18 | 0 | $(18 - 0)^2 = 324$ |
| 3.43 | 16 | 0 | $(16 - 0)^2 = 256$ |
| 4.34 | 15 | 0 | $(15 - 0)^2 = 225$ |
| 4.42 | 14 | 0 | $(14 - 0)^2 = 196$ |
| 2.37 | 24 | 0 | $(24 - 0)^2 = 576$ |

### 3. Calculate the Mean Squared Error (MSE)
Finally, we find the average of all the squared errors. We sum them up and divide by the number of data points (n=7).

$$
\text{MSE} = \frac{1}{n} \sum_{i=1}^{n} (y_i - \hat{y}_i)^2
$$

$$
\text{Sum of Squared Errors} = 324 + 225 + 324 + 256 + 225 + 196 + 576 = 2126
$$

$$
\text{MSE} = \frac{2126}{7} \approx 303.71
$$

Of course. Here are the calculations for the 2nd and 3rd gradient descent iterations.

For these calculations, we need to set a **learning rate**, which controls how big of a step we take to update our parameters. A common value is **0.01**, which we'll use here.

---
## Iteration 2

In this iteration, we start with the parameters from the beginning: $w=0$ and $b=0$. The goal is to calculate the gradients, update the parameters, and find the new, lower MSE.

### 1. Calculate Gradients
First, we calculate the gradient (the slope of the loss function) for both the weight ($w$) and the bias ($b$).

* **Gradient for w**: -119.72
* **Gradient for b**: -34.29

### 2. Update Parameters
Next, we update the weight and bias by moving in the *opposite* direction of the gradient, scaled by the learning rate.

* **New w** = $w - (\text{learning\_rate} \times \text{gradient\_w}) = 0 - (0.01 \times -119.72) = \bf{1.1972}$
* **New b** = $b - (\text{learning\_rate} \times \text{gradient\_b}) = 0 - (0.01 \times -34.29) = \bf{0.3429}$

### 3. Calculate New MSE
Using our updated parameters, we calculate the new MSE.

* **New MSE**: **170.84**

As you can see, the error dropped significantly from the initial MSE of 303.71.

---
## Detailed MSE Calculation for Iteration 2
Using the updated parameters `w=1.1972` and `b=0.3429`, we can create a detailed breakdown of the new MSE.

|   Weight (x) |   Actual MPG (y) |   Predicted MPG (ŷ) |   Error (y - ŷ) |   Squared Error (y - ŷ)² |
|-------------:|-----------------:|--------------------:|----------------:|-------------------------:|
|         3.50 |               18 |              4.5330 |         13.4670 |                 181.3612 |
|         3.69 |               15 |              4.7604 |         10.2396 |                 104.8490 |
|         3.44 |               18 |              4.4611 |         13.5389 |                 183.3011 |
|         3.43 |               16 |              4.4492 |         11.5508 |                 133.4220 |
|         4.34 |               15 |              5.5386 |          9.4614 |                  89.5184 |
|         4.42 |               14 |              5.6344 |          8.3656 |                  69.9840 |
|         2.37 |               24 |              3.1802 |         20.8198 |                 433.4660 |

**Sum of Squared Errors** = `181.36 + 104.85 + 183.30 + 133.42 + 89.52 + 69.98 + 433.47 = 1195.90`

**MSE** = Sum of Squared Errors / n = `1195.90 / 7 =` **170.84**

---
## Iteration 3

Now, we repeat the process using the updated parameters from iteration 2 ($w=1.1972$ and $b=0.3429$).

### 1. Calculate Gradients
We calculate the new gradients based on the errors from the previous iteration.

* **Gradient for w**: -85.28
* **Gradient for b**: -24.98

### 2. Update Parameters
We update the weight and bias again.

* **New w** = $1.1972 - (0.01 \times -85.28) = \bf{2.0500}$
* **New b** = $0.3429 - (0.01 \times -24.98) = \bf{0.5927}$

### 3. Calculate New MSE
Finally, we calculate the resulting MSE with the latest parameters.

* **New MSE**: **103.17**

The error continues to decrease, showing that our model is learning and improving with each iteration.


Gradient Descent calculation using simple plain python scripts. 
./gd.py
```bash
python3 gd.py
Iteration	Weight	Bias	Loss
0	0.0000	0.0000	303.7143
1	1.1972	0.3429	170.8431
2	2.0500	0.5927	103.1740
3	2.6572	0.7762	68.7028
4	3.0890	0.9123	51.1344
5	3.3957	1.0145	42.1721
6	3.6132	1.0927	37.5916


