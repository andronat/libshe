#!/usr/bin/python

import numpy as np
import matplotlib.pyplot as plt

with open("benchmark/benchmark_sumprod.txt") as f:
        data = f.read()
        kx = [float(x) for x in data.split('\n') if x.strip() != '']
        fig = plt.figure()
        y = []
        for i in range(len(kx)):
            y.append(i)
        
        ax1 = fig.add_subplot(111)
        ax1.set_title("Computation times for encrypted bit calculation in index")    
        ax1.set_xlabel('Index (bit)')
        ax1.set_ylabel('Time (ms)')

        ax1.stem(y,kx, c='r')
        leg = ax1.legend()

        plt.show()
