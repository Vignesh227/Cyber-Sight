import numpy as np
import os
import pickle
from scipy.stats import entropy
from math import log, e
import timeit
import pandas as pd
from pandas import json_normalize
import schedule
import time
import datetime
from datetime import datetime, timedelta
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import LabelEncoder
from IPython.display import display
from sklearn.metrics import silhouette_score, davies_bouldin_score, adjusted_rand_score, normalized_mutual_info_score, calinski_harabasz_score
import plotly.express as px
import plotly.offline as pyo
import plotly.io as pio


import warnings
warnings.filterwarnings("ignore")





# Func for Connection Establishment

def connectionEstablishment():
    from opensearchpy import OpenSearch
    host = 'aheesa.cdacchn.in'
    port = 9200
    auth = ('elastic', 'weMianh07CCgKzKpGKKu') # For testing only. Don't store credentials in code.
    ca_certs_path ="security/ca.crt"

    client = OpenSearch(
    hosts = [{'host': host, 'port': port}],
    http_compress = True,  # enables gzip compression for request bodies
    http_auth = auth,
    use_ssl = True,
    verify_certs = True,
    ssl_assert_hostname = False,
    ssl_show_warn = False,
    ca_certs = ca_certs_path
    )

    print(client.info() ,'\n')
    
    return client















# Func to calculate entropy 

def entropy(labels, base=None):

    n_labels = len(labels)

    if n_labels <= 1:
        return 0

    value,counts = np.unique(labels, return_counts=True)
    probs = counts / n_labels
    n_classes = np.count_nonzero(probs)

    if n_classes <= 1:
        return 0

    ent = 0.

    # Compute entropy
    base = e if base is None else base
    for i in probs:
        ent -= i * log(i, base)

    return ent












#  Function to convert Datatime into Epoch 

def datetime_to_epoch(dt):
    epoch = datetime(1970, 1, 1)
    seconds = (dt - epoch).total_seconds()
    return int(seconds)













# Code automation

def run_dbscan_clustering(start, end):
    
    client = connectionEstablishment()

    global previous_date
    global num_records

    # start_date = datetime(2023, 7, 31, 12, 2, 0)  # Set the start date to July 26
    # end_date   = datetime(2023, 8, 9, 10, 40, 0)  # Set the end date to July 27

    start_date = datetime.strptime(start, '%Y-%m-%d')
    end_date = datetime.strptime(end, '%Y-%m-%d')


    one_day = timedelta(days=1)
    
    num_records=0
    #delta = timedelta(hours=1)  # Set the time interval to 1 hour
    
    previous_date = None
    i = 1


    # Create 2 Arrays for storing graphs
    scatter_graphs = {}
    bar_graphs = {}

    # Total ip count
    totalCounts = []
    totalRecords = 0
    totalAnom = 0
    totalAnomIp = []

    # Line graph (date vs anomaly count)
    dateArr = []
    eachdayAnomaly = []

    while start_date <= end_date:
        if previous_date is None:
            previous_date = start_date + one_day
    
        
        print('-------------------------------------------------------------------------------------------------\n')

        print('\nSTART DATE :',start_date,'\nEND DATE :',previous_date)
        
        formatted_start_date = datetime_to_epoch(start_date) 
        formatted_end_date = datetime_to_epoch(previous_date) 
        

            
        index_name = "flows*"
        # field_name = "dh"

        # Update the mapping to enable fielddata for the field
        mapping = {
            "properties": {
                "dh": {
                    "type": "text",
                    "fielddata": True
                },
                "proto": {
                    "type": "text",
                    "fielddata": True
                }
            }
        }

        # Send the mapping update request
        response = client.indices.put_mapping(index=index_name, body=mapping)

        # Check if the mapping update was successful
        if response["acknowledged"]:
            print("Mapping updated successfully.")
        else:
            print("Failed to update the mapping.")
        query2 ={
            "query": {
                "bool": {
                    "must": [
                        {
                            "wildcard": {
                                "sh": "10.*"
                            }
                        },
                        {
                            "range": {
                                "fs": {
                                    "gt": formatted_start_date
                                }
                            }
                        },
                        {
                            "range": {
                                "ls": {
                                    "lt": formatted_end_date
                                }
                            }
                        }
                    ]
                }
            },
             "size": 0,
            "aggs": {
                "group_by_sh": {
                    "terms": {
                        "field": "sh",
                        "size": 10000
                    },
                    "aggs": {
                        "top_filters_hits": {
                            "terms": {
                                "size": 10000,
                                "field": "dh"
                            }
                        },
                        "top_filters_hits_srcport": {
                            "terms": {
                                "size": 10000,
                                "field": "sp"
                            }
                        },
                        "top_filters_hits_destport": {
                            "terms": {
                                "size": 10000,
                                "field": "dp"
                            }
                        },
                        "top_filters_hits_spkt": {
                            "terms": {
                                "size": 10000,
                                "field": "csp"
                            }
                        },
                        "top_filters_hits_rpkt": {
                            "terms": {
                                "size": 10000,
                                "field": "scp"
                            }
                        },
                        "top_filters_hits_duration": {
                            "terms": {
                                "size": 10000,
                                "field": "dur"
                            }
                        },
                        "top_filters_hits_proto": {
                          "terms": {
                             "size" : 10000,
                              "field": "proto"
                          }
                        }
                    }
                }
            }
        }
        
        # Fetch the data
        data2 = client.search(index="flows*",scroll='3m',size=10000,body=query2)
        
        elastic_docs = data2['aggregations']['group_by_sh']['buckets']
        
        num_records = len(elastic_docs)
        print('\n LENGTH OF FETCHED DATA : ',num_records)
        
        
        # Only if number of records > 0, continue for further steps.
        # Else skip the process, and increment start date, end date.
        if num_records > 0:
        
            df =pd.DataFrame() 
            
            # iterate the docs returned by API call   
            def add_to_dataframe(elastic_docs):   
                df =pd.DataFrame() 
                df = pd.DataFrame.from_dict([document for document in elastic_docs])     
                return df 

            df = add_to_dataframe(elastic_docs)
            display(df) 


            #Entropy of the destination bytes
            i = 1
            temp2 = []
            df['unique_dest_ip'] = ""
            df['count_of_unique_dest_ip'] = ""
            df['first_dest_ip_byte'] = ""
            df['second_dest_ip_byte'] = ""
            df['third_dest_ip_byte'] = ""
            df['fourth_dest_ip_byte'] = ""
            df['entropy_of_1_4'] = ""
            df['entropy_of_2_4'] = ""
            df['entropy_of_3_4'] = ""
            df['mean_number_of_flows_per_peer'] = ""
            no_of_flows = 0

            count = 0

            for x in df['top_filters_hits']:
                no_of_flows = 0
                temp1 = []
                first_dest_temp = []
                second_dest_temp = []
                third_dest_temp = []
                fourth_dest_temp = []
                for y in range(len(x['buckets'])):
                    no_of_flows+=1
                    if y not in temp1:
                        temp1.append(x['buckets'][y]['key'])
                        temp_split = (x['buckets'][y]['key']).split('.')
                        first_dest_temp.append(temp_split[0])
                        second_dest_temp.append(temp_split[1])
                        third_dest_temp.append(temp_split[2])
                        fourth_dest_temp.append(temp_split[3])            
                        #print(first_dest_temp)
                        #print(temp_split)
                #print(temp1)
                #print(x)
                if(len(temp1) == 0):
                    df.loc[count, 'mean_number_of_flows_per_peer'] = 0
                else:
                    # df['mean_number_of_flows_per_peer'][count] = no_of_flows/len(temp1)
                    df.loc[count, 'mean_number_of_flows_per_peer'] = no_of_flows / len(temp1)

                df['unique_dest_ip'][count] = temp1
                df['count_of_unique_dest_ip'][count] = len(temp1)
                df['first_dest_ip_byte'][count] = first_dest_temp
                df['second_dest_ip_byte'][count] = second_dest_temp
                df['third_dest_ip_byte'][count] = third_dest_temp
                df['fourth_dest_ip_byte'][count] = fourth_dest_temp
                #df['entropy_of_first_dest_ip'][count] = entropy(first_dest_temp)
                #df['entropy_of_second_dest_ip'][count] = entropy(second_dest_temp)
                #df['entropy_of_third_dest_ip'][count] = entropy(third_dest_temp)
                #df['entropy_of_fourth_dest_ip'][count] = entropy(fourth_dest_temp)
                if entropy(fourth_dest_temp) == 0:
                    df.loc[count,'entropy_of_1_4'] = 0
                    df.loc[count,'entropy_of_2_4'] = 0
                    df.loc[count,'entropy_of_3_4'] = 0
                else:
                    df.loc[count,'entropy_of_1_4'] = entropy(first_dest_temp)/entropy(fourth_dest_temp)
                    df.loc[count,'entropy_of_2_4'] = entropy(second_dest_temp)/entropy(fourth_dest_temp)
                    df.loc[count,'entropy_of_3_4'] = entropy(third_dest_temp)/entropy(fourth_dest_temp)
                    
                count+=1

            



            #Entropy of source ports
            no_of_source_ports = 0
            count1 = 0
            source_ports = []
            df['no_of_src_ports'] = ""
            df['no_of_src_ports/no_of_peers'] = ""
            df['entropy_of_source_ports'] = ""
            for x in df['top_filters_hits_srcport']:
                source_ports = []
                no_of_source_ports = 0
                for y in range(len(x['buckets'])):
                    if x['buckets'][y]['key'] not in source_ports:
                        source_ports.append(x['buckets'][y]['key'])
                        no_of_source_ports+=1
                        
                if(len(df['unique_dest_ip'][count1]) == 0):
                    df.loc[count1,'no_of_src_ports/no_of_peers'] = 0
                else:
                    df.loc[count1,'no_of_src_ports/no_of_peers'] = no_of_source_ports/len(df['unique_dest_ip'][count1])
                df.loc[count1,'entropy_of_source_ports'] = entropy(source_ports)
                df.loc[count1,'no_of_src_ports'] = no_of_source_ports
                
                count1+=1
                

            #print("--------------------------------------------------- Entropy Of Source Ports -------------------------------------")  

            #Entropy of destination ports
            no_of_dst_ports = 0
            count2 = 0
            dst_ports = []
            df['no_of_dst_ports'] = ""
            df['no_of_dst_ports/no_of_peers'] = ""
            df['entropy_of_dst_ports'] = ""
            for x in df['top_filters_hits_destport']:
                dst_ports = []
                no_of_dst_ports = 0
                for y in range(len(x['buckets'])):
                    if x['buckets'][y]['key'] not in dst_ports:
                        dst_ports.append(x['buckets'][y]['key'])
                        no_of_dst_ports+=1
                if(len(df['unique_dest_ip'][count2]) == 0):
                    df.loc[count2,'no_of_dst_ports/no_of_peers'] = 0
                else:
                    df.loc[count2,'no_of_dst_ports/no_of_peers'] = no_of_dst_ports/len(df['unique_dest_ip'][count2])
                df.loc[count2,'entropy_of_dst_ports'] = entropy(dst_ports)
                df.loc[count2,'no_of_dst_ports'] = no_of_dst_ports
                """
                print("dest_ports",no_of_dst_ports)
                print("length",len(df['unique_dest_ip'][count2]))
                print("entropy",entropy(dst_ports))
                print("ratio",df.loc[count2,'no_of_dst_ports/no_of_peers'])
                """
                count2+=1
               #print(no_of_source_ports)
               #print('count2',y)


            #print("--------------------------------------------------- Entropy Of Destination Ports -------------------------------------")  
            #display(df)  


            #Mean number of packet flow
            sent_packets = []
            df['sum_of_sent_packets'] = int()
            df['mean_no_of_packets_per_flow'] = ""
            count3 = 0
            for x in df['top_filters_hits_spkt']:
                sent_packets = []
                no_of_times = 0
                for y in range(len(x['buckets'])):
                    sent_packets.append(x['buckets'][y]['key'])
                    no_of_times+=1
                #print(sent_packets)
                #print(sum(sent_packets))
                #print(no_of_times)
                df.loc[count3,'sum_of_sent_packets'] = sum(sent_packets)
                if(no_of_times == 0):
                    df.loc[count3,'mean_no_of_packets_per_flow'] =0
                else:
                    
                    df.loc[count3,'mean_no_of_packets_per_flow'] = sum(sent_packets)/no_of_times
                #print(df.loc[count3,'mean_no_of_packets_per_flow'])
                count3+=1


            #print("--------------------------------------------------- Mean number of packet flow -------------------------------------")  
            #display(df)  

            #Duration of the flow
            dur_of_flow = []
            df['sum_of_dur_of_flow'] = ""
            df['mean_duration_of_flow'] = ""
            count4 = 0
            for x in df['top_filters_hits_duration']:
                dur_of_flow = []
                no_of_times = 0
                for y in range(len(x['buckets'])):
                    #print(x['buckets'][y]['key'])
                    dur_of_flow.append(x['buckets'][y]['key'])
                    no_of_times+=1
                    #print(no_of_times)
                #print(no_of_times)
                df.loc[count4,'sum_of_dur_of_flow'] = sum(dur_of_flow)
                if(no_of_times == 0):
                    print('inside1')
                    #df.loc[count4,'mean_duration_of_flow'] =0
                else:
                    df.loc[count4,'mean_duration_of_flow'] = sum(dur_of_flow)/no_of_times
                    #print(sum(dur_of_flow)/no_of_times)
                count4+=1

            #print("--------------------------------------------------- Duration of the flow -------------------------------------")  
            #display(df) 



            #Mean duration of the flow
            protocols = []
            df['entropy_of_protocols'] = ""
            count5 = 0
            for x in df['top_filters_hits_proto']:
                for y in range(len(x['buckets'])):
                    protocols.append(x['buckets'][y]['key'])
                df.loc[count5,'entropy_of_protocols'] = entropy(protocols)
                #print(df.loc[count5,'entropy_of_protocols'])
                count5+=1 
                #print(entropy(protocols))


            #print("--------------------------------------------------- Mean duration of flow -------------------------------------")  


            from sklearn import preprocessing
            from sklearn.preprocessing import MinMaxScaler
            scaler = MinMaxScaler()


            le = preprocessing.LabelEncoder()
            df['key_updated'] = le.fit_transform(df['key'].values)

        
            store_df = df[['key','count_of_unique_dest_ip','entropy_of_1_4','entropy_of_2_4','entropy_of_3_4',
                        'no_of_src_ports/no_of_peers','entropy_of_source_ports','no_of_dst_ports/no_of_peers',
                        'entropy_of_dst_ports','mean_no_of_packets_per_flow','mean_number_of_flows_per_peer',
                        'mean_duration_of_flow','entropy_of_protocols']].copy()
            
            df['count_of_unique_dest_ip_norm'] = scaler.fit_transform(df[['count_of_unique_dest_ip']])
            df['entropy_of_1_4_norm'] = scaler.fit_transform(df[['entropy_of_1_4']])
            df['entropy_of_2_4_norm'] = scaler.fit_transform(df[['entropy_of_2_4']])
            df['entropy_of_3_4_norm'] = scaler.fit_transform(df[['entropy_of_3_4']])
            df['no_of_src_ports/no_of_peers_norm'] = scaler.fit_transform(df[['no_of_src_ports/no_of_peers']])
            df['entropy_of_source_ports_norm'] = scaler.fit_transform(df[['entropy_of_source_ports']])
            df['no_of_dst_ports/no_of_peers_norm'] = scaler.fit_transform(df[['no_of_dst_ports/no_of_peers']])
            df['entropy_of_dst_ports_norm'] = scaler.fit_transform(df[["entropy_of_dst_ports"]])
            df['mean_no_of_packets_per_flow_norm'] = scaler.fit_transform(df[['mean_no_of_packets_per_flow']])
            df['mean_number_of_flows_per_peer_norm'] = scaler.fit_transform(df[['mean_number_of_flows_per_peer']])
            df['mean_duration_nan'] = pd.to_numeric(df['mean_duration_of_flow'],errors='coerce')
            df['mean_duration_of_flow_norm'] = scaler.fit_transform(df[['mean_duration_nan']])
            df['protocols_nan'] = pd.to_numeric(df['entropy_of_protocols'],errors='coerce')
            df['entropy_of_protocols_norm'] = scaler.fit_transform(df[['protocols_nan']])

            #print("df")
            #print("Final DataFrame After Scaling the features")
            #display(df)
            dataset = pd.DataFrame()
            data = pd.DataFrame()
            dataset = df[['key','key_updated','count_of_unique_dest_ip_norm','entropy_of_1_4_norm','entropy_of_2_4_norm','entropy_of_3_4_norm',
                        'no_of_src_ports/no_of_peers_norm','entropy_of_source_ports_norm','no_of_dst_ports/no_of_peers_norm',
                        'entropy_of_dst_ports_norm','mean_no_of_packets_per_flow_norm','mean_number_of_flows_per_peer_norm',
                        'mean_duration_of_flow_norm','entropy_of_protocols_norm']].copy()


            dataset.fillna(0,inplace=True)
            data = dataset.iloc[:,1:14]
            
            data.fillna(0,inplace=True)
            
            # model_file_path = "dbscanmodel.pkl"
            
            if not os.path.isfile('dbscanmodel.pkl'):
                incremental_dbscan = IncrementalDBSCAN(eps=2.05, min_samples=3)
                incremental_dbscan.fit(data)
                
                # Call the function to create a table in postgres DB
                # create_table()

            else:
            
                incremental_dbscan.load_model('dbscanmodel.pkl')
                incremental_dbscan.update(data)

            # Save the model
            incremental_dbscan.save_model("dbscanmodel.pkl")
            
            # Get the cluster labels
            updated_labels = incremental_dbscan.dbscan_model.labels_
            # print("\n Updated Cluster Labels:", updated_labels)




            # Calculate DBSCAN clustering evaluation metrics
            # silhouette_avg = silhouette_score(data, updated_labels)
            # davies_bouldin = davies_bouldin_score(data, updated_labels)
            # calinski_harabasz = calinski_harabasz_score(data, updated_labels)

            # Print the results
            # print("Silhouette Score:", silhouette_avg) #Higher - Better (0-1)
            # print("Davies-Bouldin Index:", davies_bouldin) #Lower - Better (0-1)
            # print("Calinski-Harabasz Index:", calinski_harabasz) #Higher - better (No range)





            # Create a DataFrame for visualizations
            graph = pd.DataFrame()
            graph['ip'] = store_df['key']
            graph['label'] = updated_labels
            
            # display(graph)


            # Scatter Plot
            scatter_fig = px.scatter(graph, x='label', y='ip', color='label',labels={'label': 'Label', 'ip': 'IP'})
            scatter_fig.update_traces(textposition='top center')
            scatter_fig.update_layout(
                template='plotly_dark',
                title='Scatter Plot of Labels vs. IPs',
                xaxis_title='Cluster Labels',
                yaxis_title='IP\'s'
            )

            # Bar Plot
            bar_fig = px.bar(graph['label'].value_counts().reset_index(), x='index', y='label', labels={'index': 'Label', 'label': 'Count'})
            # bar_fig.update_traces(textposition='top center')
            bar_fig.update_layout(
                template='plotly_dark',
                title='Bar Plot of Label Counts',
                xaxis_title='Cluster Labels',
                yaxis_title='Count'
            )

            # Show both plots side by side
            # scatter_fig.show()
            # bar_fig.show()

            # scatter_graphs.append(scatter_fig)
            # bar_graphs.append(bar_fig)



            key=f'{start_date}'

            # Trim the date alone 
            key = key[:10]

            # Plot the graphs
            scatter_graphs[key] = pyo.plot(scatter_fig, include_plotlyjs=False, output_type='div')
            bar_graphs[key] = pyo.plot(bar_fig, include_plotlyjs=False, output_type='div')



            i += 1

            





            
            # Display anomalies
            dataset = display_anomalies(updated_labels, dataset)
            store_df['anomaly'] = dataset['anomaly']
            
            # Add datetime (timestamp) to final dataset             
            timestamp = start_date.strftime('%Y-%m-%d %H:%M:%S')
            store_df['timestamp'] = timestamp
            
            
            # BRING THE DATE COLUMN (last col) TO FRONT (first colmn)
            # Get the column names and rearrange them 
            column_names = store_df.columns.tolist()
            column_names = [column_names[-1]] + column_names[:-1]

            # Store it in the main dataFrame with the desired column order
            store_df = store_df[column_names]
            
            

            dataset = dataset.drop(['key_updated'], axis=1)
            print("\n FINAL DATASET : ")
            display(store_df)
            
            
            # Insert data into PostgresSQL
            # insert_data(store_df)
        
        
        # Total Records for Cards Vsualization
        totalRecords += store_df['key'].count()

        # Total count of Anomalous IP
        totalAnom += (store_df[store_df['anomaly'] == 1])['anomaly'].count()

        # Anamalous IP's List
        
        # tempArr = (store_df[store_df['anomaly'] == 1])['key'].unique()
        # totalAnomIp.append()

        tempArr = []
        tempArr = (store_df[store_df['anomaly'] == 1])['key'].unique()
    
        for i in tempArr:
            totalAnomIp.append(i)
        



        print('\n Total anom ip : ',totalAnomIp)
        


        # Append the dates for line graph ( Date vs Anomaly Counts)
        
        dateArr.append(key)
        eachdayAnomaly.append((store_df[store_df['anomaly'] == 1])['anomaly'].count())
        


        start_date = previous_date
        previous_date = previous_date+one_day
        
        # print('\n Total anomaly : ',total_anomaly)
        
        print('\n-------------------------------------------------------------------------------------------------')
    
    # Remove duplicates from Total Anomalous IP's
    totalAnomIp = set(totalAnomIp)
    result_string = ', '.join(totalAnomIp)


    

    
    # Create a line chart with Plotly Express
    line_fig = px.line(x=dateArr, y=eachdayAnomaly, labels={'x': 'Date', 'y': 'Anomaly Count'})

    # Update the layout with the desired theme and formatting
    line_fig.update_layout(
        template='plotly_dark',  # Set the theme here (e.g., 'plotly', 'plotly_dark', 'ggplot2')
        title='Line Chart of Anomaly Counts Over Time',
        xaxis_title='Date',
        yaxis_title='Anomaly Count'
    )

    line_graphs = pyo.plot(line_fig, include_plotlyjs=False, output_type='div')

    


    totalCounts = [totalRecords, totalAnom, result_string]
    print('\n\n - - - - - - PROCESS COMPLETED - - - - - - ')


    return scatter_graphs, bar_graphs, totalCounts, line_graphs









# Function to display the anomalous IP's and to create a separate anomaly column 1-> anom 0-> Not anom

total_anomaly= []
def display_anomalies(labels, df):
    anomaly=[]
    for i in range(len(labels)):
        if((labels[i] == -1) and (df['key'][i] not in anomaly)):
            anomaly.append(df['key'][i])
            total_anomaly.append(df['key'][i])
                   
    print("\n Anomalous IP's : ", anomaly)
    
    
    # Create the 'anomaly' column and set values based on the 'anom' list
    df['anomaly'] = 0  # Initialize all values in the 'anomaly' column to 0

    for i in df.index:
        if labels[i] == -1:
            df.loc[i, 'anomaly'] = 1
    
    return df







# Save the list to a file

def save_self_rep(selfrep):
    with open('self_rep_aheesa_data.pkl', 'wb') as file:
        pickle.dump(selfrep, file)







from sklearn.cluster import DBSCAN

class IncrementalDBSCAN:
    def __init__(self, eps, min_samples, max_representatives=500):
        self.eps = eps
        self.min_samples = min_samples
        self.max_representatives = max_representatives
        self.dbscan_model = None
        self.representatives = None
    
    def save_model(self, file_path):
        # Save the fitted model to a file
        with open(file_path, 'wb') as file:
            pickle.dump(self.dbscan_model, file)

    def load_model(self, file_path):
        # Load the saved model from the file
        with open(file_path, 'rb') as file:
            self.dbscan_model = pickle.load(file)
            
        # load the self representative list from the file
        with open('self_rep_aheesa_data.pkl', 'rb') as file:
            self.representatives = pickle.load(file)
            
    def fit(self, X):
        
        # Convert DataFrame to numpy array
        X = X.values
        
        # Initialize a new DBSCAN model
        self.dbscan_model = DBSCAN(eps=self.eps, min_samples=self.min_samples)
        
        # Train the model on the data
        self.dbscan_model.fit(X)
        
        # Initialize representatives with all unique data points from the initial dataset
        self.representatives = np.unique(X, axis=0)

        # Limit the number of representatives to the maximum allowed
        self.representatives = self.representatives[:min(self.max_representatives, len(self.representatives))]
        
        # Func call
        save_self_rep(self.representatives)
        

    def update(self, new_data):
        # Convert DataFrame to numpy array
        new_data = new_data.values
        
        # Predict cluster labels for all new data points at once
        new_labels = self.dbscan_model.fit_predict(new_data)
        
        max_label = np.max(self.dbscan_model.labels_)  # Get the maximum label from existing clusters

        for new_label in np.unique(new_labels):
            if new_label == -1:
                # Noise points in the new data, skip them
                continue

            cluster_points = new_data[new_labels == new_label]
            distances = np.linalg.norm(cluster_points - self.representatives[:, np.newaxis], axis=-1)
            core_distances = np.sort(distances, axis=1)[:, self.min_samples - 1]
            core_distances_sorted = np.sort(core_distances)
            # print(cluster_points)
            for idx, point in enumerate(cluster_points):
                distance = distances[idx]
                core_distance = core_distances_sorted[idx]

                if core_distance > self.eps:
                    # The point is not density-reachable, assign a new label
                    max_label += 1
                    self.dbscan_model.labels_[new_labels == new_label][idx] = max_label
                else:
                    # The point is density-reachable, find the nearest core point
                    is_core_point = distance <= core_distance
                    if is_core_point.any():
                        nearest_core_idx = np.argmin(distance[is_core_point])
                        nearest_core_label = self.dbscan_model.labels_[new_labels == new_label][is_core_point][nearest_core_idx]
                        self.dbscan_model.labels_[new_labels == new_label][idx] = nearest_core_label
                    else:
                        # The point is not density-reachable, assign a new label
                        max_label += 1
                        self.dbscan_model.labels_[new_labels == new_label][idx] = max_label

        # Update representatives with new data points
        num_new_representatives = min(self.max_representatives, new_data.shape[0])
        new_representatives_idx = np.random.choice(new_data.shape[0], num_new_representatives, replace=False)
        self.representatives = np.vstack((self.representatives, new_data[new_representatives_idx]))
        
        # Func call
        save_self_rep(self.representatives)

