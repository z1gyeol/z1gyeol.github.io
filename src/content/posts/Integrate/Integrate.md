---
title: Integrating P(x)e^x
published: 2024-08-06
description: ''
image: ''
tags: [math, calculus]
category: 'Math'
draft: false 
---
# Intro
어제 수학 풀다가 갑자기 생각나서 해봤다.
이 글은 $\displaystyle\int x^ne^xdx$와 임의의 다항식 $P(x)$에 대하여 $\displaystyle\int P(x)e^xdx$에 대해 다룬다.
# Solution
## $\displaystyle\int x^ne^xdx$
우선 차수가 $m$인 다항식과 $e^x$을 곱한 함수는 미분해도  차수가 $m$인 다항식과 $e^x$의 곱으로 이루어진 함수이다.

$${d \over dx}[\text{\textbraceleft} x^m+P_1(x)\text{\textbraceright}e^x]=\text{\textbraceleft}x^m+P_2(x)\text{\textbraceright}e^x$$

이런 식으로 말이다.
즉 $x^ne^x$을 적분하면 차수가 $n$인 다항식 $P(x)$와 $e^x$을 곱한 함수가 나올 것이라는 것을 예상할 수 있다.
그럼 
$$\int x^ne^xdx=P(x)e^x+C$$

라는 관계식을 세울 수 있다. 양변을 미분하면
$$x^ne^x=e^x \text{\textbraceleft} P(x)+P^{\prime}(x) \text{\textbraceright}$$

 이다. 따라서 $x^n=P(x)+P^{\prime}(x)$이다. 이때 $P(x)$와 $P^{\prime}(x)$는 다항식이므로 다음과 같이 쓸 수 있다.
 $$P(x)=\sum_{i=0}^na_ix^i=a_nx^n+\sum_{i=0}^{n-1}a_ix^i\\
 P^{\prime}(x)=\sum_{i=0}^{n-1}(i+1)a_{i+1}x^i$$
 그러면 $P(x)+P^{\prime}(x)$는 다음과 같다.
 $$a_nx^n+\sum_{i=0}^{n-1}a_ix^i+\sum_{i=0}^{n-1}(i+1)a_{i+1}x^i=a_nx^n+\sum_{i=0}^{n-1}x^i\text{\textbraceleft}a_i+(i+1)a_{i+1}\text{\textbraceright}=x^n$$
 따라서 $a_n=1$이고 $\displaystyle\sum_{i=0}^{n-1}x^i\text{\textbraceleft}a_i+(i+1)a_{i+1}\text{\textbraceright}=0$이 되어야 하므로 
 $$a_i+(i+1)a_{i+1}=0$$
 
 $a_i=-(i+1)a_{i+1}$이므로
 > $a_n=1$<br>
 > $a_{n-1}=-n$<br>
 > $a_{n-2}=n(n-1)$<br>
 > $a_{n-3}=-n(n-1)(n-2)$<br>
 > ...<br>
 > $a_i=(-1)^{n-i}\sdot\Large{n!\over i!}$<br>
 >...
 
 라는 것을 알 수 있다. 그러므로
 $$P(x)=\sum_{i=0}^n(-1)^{n-i}\sdot{n!\over i!}\sdot x^i$$
 따라서
 $$\int x^ne^xdx=e^x\sum_{i=0}^n(-1)^{n-i}\sdot{n!\over i!}\sdot x^i+C$$
 ## $\displaystyle\int P(x)e^xdx$
 이번엔 조금 더 일반적인 경우이다. 우선 $P(x)=\displaystyle\sum_{i=0}^na_ix^i$와 $P_1(x)=\displaystyle\sum_{i=0}^nb_ix^i$에 대하여 $\displaystyle\int P(x)e^xdx=P_1(x)e^x+C$임을 이전 과정을 통해 알 수 있다. 아까와 동일하게 양변을 미분함으로써 $P(x)=P_1(x)+P_1^{\prime}(x)$임을 알 수 있다.
 $$P_1(x)+P_1^{\prime}(x)=b_nx^n+\sum_{i=0}^{n-1}x^i\text{\textbraceleft}b_i+(i+1)b_{i+1}\text{\textbraceright}$$
 이므로 $b_n=a_n$이고 $b_i+(i+1)b_{i+1}=a_i$이다.
 따라서
 >$b_n=a_n$<br>
 >$b_{n-1}=a_{n-1}-na_n$<br>
 >$b_{n-2}=a_{n-2}-(n-1)a_{n-1}+n(n-1)a_n$<br>
 >$b_{n-3}=a_{n-3}-(n-2)a_{n-2}+(n-1)(n-2)a_{n-1}-n(n-1)(n-2)a_n$<br>
 >...<br>
 >$b_i=\displaystyle\sum_{j=i}^n(-1)^{j-i}\sdot{j!\over i!}\sdot a_j$<br>
 >...
 
이다. 그러므로
$$P_1(x)=\sum_{i=0}^n\Large(\normalsize x^i\sum_{j=i}^n(-1)^{j-i}\sdot{j!\over i!}\sdot a_j\Large)$$
이므로
$$\displaystyle\int\Large( \normalsize e^x\displaystyle\sum_{i=0}^na_ix^i\Large)\normalsize dx=e^x\sum_{i=0}^n\Large(\normalsize x^i\sum_{j=i}^n(-1)^{j-i}\sdot{j!\over i!}\sdot a_j\Large)\normalsize+C$$
<br><br><br><br>



Well Done
![image](./thumb.jpg)