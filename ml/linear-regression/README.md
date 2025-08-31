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


