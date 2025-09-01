import math
import math
x_values=[3.5,3.69,3.44,3.43,4.34,4.42,2.37]
y_values=[18,15,18,16,15,14,24]
alpha=0.01

def predict(m,b):
    p=[]
    for i in range(len(x_values)):
        pi=m*x_values[i]+b
        p.append(pi)
    return p

def mse(p):
    se=0
    for i in range(len(y_values)):
        se+=math.pow((y_values[i]-p[i]),2)
    return se/len(y_values)


def weightSlope(p):
    ws=0
    for i in range(len(p)):
        ws+=x_values[i]*(y_values[i]-p[i])
    return 2*-ws/len(p)

def biasSlope(p):
    bs=0
    for i in range(len(p)):
        bs+=y_values[i]-p[i]
    return 2*-bs/len(p)

def newBias(oldBias,biasSlope):
   return oldBias - alpha*biasSlope

def newWeight(oldWeight,weightSlope):
    return oldWeight-alpha*weightSlope

def main():
    m=0
    b=0
    print(f"{'Iteration':<12} | {'Weight':<10} | {'Bias':<10} | {'Loss'}")
    print("-" * 50) # A separator line for clarity
    for i in range(7):
        p=predict(m,b)
        loss=mse(p)
        print(f"{i:<12} | {m:<10.4f} | {b:<10.4f} | {loss:.4f}")
        m=newWeight(m,weightSlope(p))
        b=newBias(b,biasSlope(p))
        

main()
