import pickle
import re
import pandas as pd
import numpy as np
import json
import boto3
import random
import warnings
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import time
import os

warnings.filterwarnings("ignore")

# Cargar el modelo guardado
with open('./modelo/dbscan_model.pkl', 'rb') as file:
    my_model = pickle.load(file)
with open('./modelo/nbrs.pkl', 'rb') as file:
    my_nbrs = pickle.load(file)
with open('./modelo/scaler.pkl', 'rb') as file:
    my_scaler = pickle.load(file)

acl_public_subnet_id = os.environ.get('ID_ACL_PUBLIC_SUBNET')
ip_elastic = os.environ.get('IP_ELASTIC')
port_elastic = os.environ.get('PORT_ELASTIC')

def is_ip_in_range(ip):
    pattern1 = re.compile(r'^169\.254\.\d{1,3}\.\d{1,3}$')
    pattern2 = re.compile(r'^192\.168\.\d{1,3}\.\d{1,3}$')

    return bool(pattern1.match(ip) or pattern2.match(ip))

def count_open_requests(x):
    return x['event.end'].isnull().sum()

def preprocesamiento(data):
  try:
    cols_clustering = ['@timestamp', 'destination.ip', 'source.ip', 'source.bytes', 'destination.bytes', 'event.duration','http.request.body.bytes', 'http.response.body.bytes', 'event.end']
    test_real_data = data[cols_clustering]

    test_real_data['@timestamp'] = pd.to_datetime(test_real_data['@timestamp'])
    test_real_data['event.end'] = pd.to_datetime(test_real_data['event.end'])

    test_real_data['@timestamp'] = test_real_data['@timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    test_real_data['event.end'] = test_real_data['event.end'].dt.strftime('%Y-%m-%d %H:%M:%S')

    test_real_data['source.bytes'].replace({np.NAN: 0}, inplace=True)
    test_real_data['destination.bytes'].replace({np.NAN: 0}, inplace=True)
    test_real_data['event.duration'].replace({np.NAN: 0}, inplace=True)
    test_real_data['http.response.body.bytes'].replace({np.NAN: 0}, inplace=True)
    test_real_data['http.request.body.bytes'].replace({np.NAN: 0}, inplace=True)

    test_real_data = test_real_data[~test_real_data['destination.ip'].apply(is_ip_in_range)]
    test_real_data = test_real_data[~test_real_data['source.ip'].apply(is_ip_in_range)]
    test_real_data = test_real_data[test_real_data['source.ip'] != '10.0.0.133']

    real_data_grouped_df = test_real_data.groupby(['@timestamp', 'destination.ip', 'source.ip'])

    real_clustering_df = real_data_grouped_df.agg({
        'source.ip': lambda x: x.mode().iloc[0],
        'source.bytes': 'sum',
        'destination.bytes': 'sum',
        'event.duration': 'sum',
        'http.response.body.bytes': 'sum',
        'http.request.body.bytes': 'sum',
        '@timestamp': 'count',
    })

    real_clustering_df = real_clustering_df.rename(columns={'@timestamp': 'count_requests'})

    real_clustering_df['open_requests'] = real_data_grouped_df.apply(count_open_requests)

    ips = real_clustering_df['source.ip']
    final_real_data = real_clustering_df[['source.bytes', 'destination.bytes', 'event.duration', 'count_requests', 'open_requests','http.request.body.bytes', 'http.response.body.bytes']]

    final_real_data = my_scaler.transform(final_real_data)
  except Exception as e:
    print(e)
    return None, None

  return final_real_data, ips

def block_ip(ip):
  ec2_client = boto3.client('ec2', region_name='us-east-1')

  rule = {
      'CidrBlock' : f"{ip}/32",
      'Egress' : False,
      'RuleAction' : "deny",
      'RuleNumber' : random.randint(1,9000)
  }

  ec2_client.create_network_acl_entry(NetworkAclId=acl_public_subnet_id,
                                      RuleNumber=rule['RuleNumber'],
                                      Protocol="-1",
                                      PortRange={'From' : 0, 'To' : 65535},
                                      CidrBlock=rule['CidrBlock'],
                                      Egress=rule['Egress'],
                                      RuleAction=rule['RuleAction'])
  

def main():
    try:

        # Configuración de la conexión a Elasticsearch
        es = Elasticsearch([{'host': "10.0.2.130", 'port': 9200, 'scheme': 'http'}])
        blocked_ips = []
        print("Conexión con ElasticSearch establecida")

        while True:
            # Tiempo actual
            current_time = datetime.utcnow()

            # Rango de tiempo para la consulta (último segundo)
            query_range = {
                "range": {
                    "@timestamp": {
                        "gte": (current_time - timedelta(seconds=20)).isoformat(),
                        "lt": (current_time - timedelta(seconds=2)).isoformat(),
                    }
                }
            }

            # Consulta a Elasticsearch
            result = es.search(
                index="packetbeat-*",
                body={
                    "query": query_range
                },
                size=10000
            )

            # Procesamiento de los resultados y creación de DataFrame
            data = []
            for hit in result['hits']['hits']:
                data.append(hit['_source'])

            df = pd.json_normalize(data)

            if len(df.columns) > 0:
                final_real_data, ips = preprocesamiento(df)

                if final_real_data is not None:

                    for x in range(len(final_real_data)):
                        traffic = np.array([list(final_real_data[x])])
                        distances, indices = my_nbrs.kneighbors(traffic)
                        cluster = my_model.labels_[indices[0][0]]

                        if cluster != 0:
                            if cluster == 1:
                                print(f'Ataque Slowloris detectado desde la ip {ips[x]}')
                            elif cluster == -1:
                                print(f'Ataque HTTP Flood detectado desde la ip {ips[x]}')
                            if ips[x] not in blocked_ips:
                                print(f"Bloqueando la ip {ips[x]}")
                                blocked_ips.append(ips[x])
                                block_ip(ips[x])


            time.sleep(2)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()