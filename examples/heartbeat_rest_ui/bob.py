import collections
import json
import random
import sqlite3
import time
from base64 import b64decode

import dash_core_components as dcc
import dash_html_components as html
import pandas as pd
import requests
from dash.dependencies import Output, Input, State, Event
from plotly.graph_objs import Scatter, Layout
from plotly.graph_objs.layout import Margin
from plotly.graph_objs.scatter import *

from examples.heartbeat_rest_ui.app import app, DB_FILE, DB_NAME, POLICY_INFO_FILE

ACCESS_DISALLOWED = "Access Disallowed"

BOB_URL = "http://localhost:{}"

bob_control_instances = dict()  # Map: bob_port -> bob instance

# different entities that Bob could be - Doctor should always be in index 0
ID_PREFIXES = ['Doctor', 'Cardiologist', 'Nutritionist', 'Nurse', 'Dietitian']


#############
# UI Layout #
#############

def get_layout(first_bob: bool):
    prefix = ID_PREFIXES[0]
    if not first_bob:
        # prefix from random index in prefixes list
        index = random.randint(0, (len(ID_PREFIXES) - 1))
        prefix = ID_PREFIXES[index]

    print('Initializing UI for Bob ({})'.format(prefix))

    # generate ui layout
    layout = html.Div([
        html.Div([
            html.Img(src='./assets/nucypher_logo.png'),
        ], className='banner'),
        html.Div([
            html.Div([
                html.Div([
                    html.Img(src='./assets/bob.png'),
                ], className='two columns'),
                html.Div([
                    html.Div([
                        html.H2('{} BOB'.format(prefix.upper())),
                        html.P(
                            "{} Bob is the {} who Alicia will grant access to her encrypted heart rate measurements "
                            "(which was populated by the Heart Monitor) and requests "
                            "a re-encrypted ciphertext for each measurement, which can then be decrypted "
                            "using their private key.".format(prefix, prefix)),
                    ], className="row")
                ], className='five columns'),
            ], className='row'),
        ], className='app_name'),
        html.Hr(),
        html.Div([
            html.H3('Heartbeats from Encrypted DB'),
            html.Div([
                html.Div("Bob's Port:", className='two columns'),
                dcc.Input(id='bob-port', type='number', className="two columns")
            ], className='row'),
            html.Div([
                html.Div("Bob's Encrypting Key (hex):", className='two columns'),
                dcc.Input(id='bob-enc-key', type='text', className="seven columns")
            ], className='row'),
            html.Div([
                html.Button('Read Heartbeats', id='read-button', type='submit',
                            className='button button-primary', n_clicks_timestamp='0'),
            ], className='row'),
            html.Div(id='heartbeats', className='row'),
            dcc.Interval(id='heartbeat-update', interval=1000, n_intervals=0),
        ], className='row'),
        # Hidden div inside the app that stores previously decrypted heartbeats
        html.Div(id='latest-decrypted-heartbeats', style={'display': 'none'})
    ])

    return layout


#################
# Bob's Actions #
#################
policy_joined = dict()  # Map: bob_port -> policy_label


@app.callback(
    Output('latest-decrypted-heartbeats', 'children'),
    [],
    [State('read-button', 'n_clicks_timestamp'),
     State('latest-decrypted-heartbeats', 'children'),
     State('bob-port', 'value'),
     State('bob-enc-key', 'value')],
    [Event('heartbeat-update', 'interval'),
     Event('read-button', 'click')]
)
def update_cached_decrypted_heartbeats_list(read_time,
                                            json_latest_values,
                                            bob_port,
                                            bob_enc_key_hex):
    if int(read_time) == 0:
        # button never clicked but triggered by interval
        return None

    # Let's join the policy generated by Alicia. We just need some info about it.
    try:
        with open(POLICY_INFO_FILE.format(bob_enc_key_hex), 'r') as f:
            policy_data = json.load(f)
    except FileNotFoundError:
        print("No policy file available")
        return ACCESS_DISALLOWED

    policy_label = policy_data['label']
    alice_sig_key_hex = policy_data['alice_verifying_key']
    policy_enc_key_hex = policy_data['policy_encrypting_key']

    if bob_port not in policy_joined:
        # Use Bob's Character control to join policy
        request_data = {
            'label': policy_label,
            'alice_verifying_key': alice_sig_key_hex,
        }
        response = requests.post(f'{BOB_URL.format(bob_port)}/join_policy', data=json.dumps(request_data))
        if response.status_code != 200:
            print(f'> WARNING: Bob (port:{bob_port}) was unable to join policy {policy_label}; '
                  f'status code = {response.status_code}')
            return ACCESS_DISALLOWED

        print(f'Bob (port:{bob_port}) joined policy with label {policy_label}')
        policy_joined[bob_port] = policy_label

    cached_hb_values = collections.OrderedDict()
    if (json_latest_values is not None) and (json_latest_values != ACCESS_DISALLOWED):
        cached_hb_values = json.loads(json_latest_values, object_pairs_hook=collections.OrderedDict)

    last_timestamp = time.time() - 5  # last 5s
    if len(cached_hb_values) > 0:
        # use last timestamp
        last_timestamp = list(cached_hb_values.keys())[-1]

    db_conn = sqlite3.connect(DB_FILE)
    try:
        df = pd.read_sql_query(f'SELECT Timestamp, EncryptedData '
                               f'FROM {DB_NAME} '
                               f'WHERE Timestamp > "{last_timestamp}" '
                               f'ORDER BY Timestamp;',
                               db_conn)

        for index, row in df.iterrows():
            message_kit_b64 = row['EncryptedData']

            # Now he can ask the NuCypher network to get a re-encrypted version of each MessageKit.
            # Use Bob's character control to retrieve re-encrypted data
            request_data = {
                'label': policy_label,
                'policy_encrypting_key': policy_enc_key_hex,
                'alice_verifying_key': alice_sig_key_hex,
                'message_kit': message_kit_b64,
            }

            response = requests.post('{}/retrieve'.format(BOB_URL.format(bob_port)), data=json.dumps(request_data))
            if response.status_code != 200:
                # TODO do something - is access disallowed the only case here? NotEnoughUrsulas?
                print(f'> WARNING: Unable to retrieve re-encryption plaintext for Bob (port: {bob_port}); '
                      f'status code = {response.status_code}; response = {response.content}')
                policy_joined.pop(bob_port, None)
                return ACCESS_DISALLOWED

            response_data = json.loads(response.content)
            plaintext = response_data['result']['cleartexts'][0]
            hb = int(b64decode(plaintext))

            # cache measurement
            timestamp = row['Timestamp']
            cached_hb_values[timestamp] = hb
    finally:
        db_conn.close()

    # only cache last 30s
    while len(cached_hb_values) > 30:
        cached_hb_values.popitem(False)

    return json.dumps(cached_hb_values)


@app.callback(
    Output('heartbeats', 'children'),
    [Input('latest-decrypted-heartbeats', 'children')]
)
def update_graph(json_cached_readings):
    if json_cached_readings is None:
        return ''

    if json_cached_readings == ACCESS_DISALLOWED:
        return html.Div('Your access has either not been granted or has been revoked!', style={'color': 'red'})

    cached_hb_values = json.loads(json_cached_readings, object_pairs_hook=collections.OrderedDict)
    if len(cached_hb_values) == 0:
        return ''

    df = pd.DataFrame({'HB': list(cached_hb_values.values())})

    trace = Scatter(
        y=df['HB'],
        line=Line(
            color='#1E65F3'
        ),
        mode='lines+markers',
    )

    graph_layout = Layout(
        height=450,
        xaxis=dict(
            title='Time Elapsed (sec)',
            range=[0, 30],
            showgrid=False,
            showline=True,
            zeroline=False,
            fixedrange=True,
            tickvals=[0, 10, 20, 30],
            ticktext=['30', '20', '10', '0']
        ),
        yaxis=dict(
            title='Heart Rate (bpm)',
            range=[50, 110],
            showline=True,
            fixedrange=True,
            zeroline=False,
            nticks=10
        ),
        margin=Margin(
            t=45,
            l=50,
            r=50
        )
    )

    return dcc.Graph(id='hb_table', figure={'data': [trace], 'layout': graph_layout})
