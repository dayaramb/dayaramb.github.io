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
y= mx + b.


## Model Parameters: Weights and Bias

To create the relationship between X and Y, the model learns two types of parameters:

### **Weights (Slope)**

A **weight** is a number that represents the importance of each input feature (X). It's like the **slope** of a line—it determines how much a change in an input feature affects the output prediction (Y).

### **Bias (Y-Intercept)**

The **bias** is a single number that acts as a baseline for predictions. It's like the **y-intercept** of a line, allowing the model to shift its output up or down to better fit the data, even when all input features are zero.

![Mathematical representation of a simple linear model](./bias-weight.png)



## Models with multiple Features:

Y' = b + w1x + w2x2 +w3x3 + w4x4 + w5 x5

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
