from tracemalloc import start
from flask import Flask,render_template,request
import numpy as np
import sklearn
import pickle
import pandas as pd
import datetime

# Import Ip Profiling File
from ipprofiling import *


app=Flask(__name__)

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/visualization')
def visualization():
    return render_template('visualization.html')

@app.route('/visualize', methods=['POST'])
def visualize():
    if request.method == 'POST':

        startdate = request.form['start']
        
        enddate = request.form['end']

        usecase = request.form['usecase']        

        # print(start, '\n', end)

        # print('\n',startdate,'\n', enddate, '\n',usecase,'\n')

        # Call the function
        scatter_graphs, bar_graphs, totalCounts, line_graphs = run_dbscan_clustering(startdate, enddate)

        
        
        return render_template('visualization.html', scatter = scatter_graphs, bar = bar_graphs, total = totalCounts
        ,line = line_graphs)


if __name__=="__main__":
    app.run(debug=True,host='0.0.0.0',port=5000)