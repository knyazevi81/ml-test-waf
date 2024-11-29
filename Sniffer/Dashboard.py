import dash
import plotly.graph_objects as go
import numpy as np
import json
import os
from DBController import DBController
from flask import Flask, render_template
from dash import html
from dash import dash_table
from dash import dcc
from plotly.subplots import make_subplots
from dash.dependencies import Input, Output

possible_attacks = ['sqli', 'xss', 'cmdi', 'path-traversal', 'valid', 'parameter-tampering']


def generate_figure(df):
    fig = make_subplots(rows = 1, cols = 3, specs=[[{'type':'domain'}, {'type':'domain'}, {'type':'domain'}]])

    fig.layout['clickmode'] = 'event+select'

    # build pie chart for performed requests
    valid_data = df.replace(['sqli', 'xss', 'cmdi', 'path-traversal', 'parameter-tampering'], 'attack')
    data_pie = valid_data['threat_type'].value_counts().to_frame()
    data_pie['type'] = list(data_pie.index)
    data_pie = data_pie.rename(columns={"threat_type": "count"})
    fig.add_trace(go.Pie(labels = data_pie['type'], values = data_pie['count'], title = 'Performed requests', textposition='inside', textinfo='percent+label'), 1, 1)

    # build pie chart for performed attacks
    attack_data = df[df['threat_type'] != 'valid']
    data_pie = attack_data['threat_type'].value_counts().to_frame()
    data_pie['type'] = list(data_pie.index)
    data_pie = data_pie.rename(columns={"threat_type": "count"})
    fig.add_trace(go.Pie(labels = data_pie['type'], values = data_pie['count'], title = 'Performed attacks', textposition='inside', textinfo='percent+label'), 1, 2)

    # build pie chart for locations of attacks
    data_pie = df['location'].value_counts().to_frame()
    data_pie['type'] = list(data_pie.index)
    data_pie = data_pie.rename(columns={"location": "count"})
    data_pie = data_pie.replace('', np.nan).dropna()
    fig.add_trace(go.Pie(labels = data_pie['type'], values = data_pie['count'], title = 'Locations of attacks', textposition='inside', textinfo='percent+label'), 1, 3)

    return dcc.Graph(
        id='example-graph1',
        figure=fig
    )


def configure_columns(name):
    config = {'name': name, 'id': name}
    if name == 'Link':
        config['presentation'] = 'markdown'
    return config


def generate_table(df, label):
    if label is None:
        data_to_use = df
    elif label == 'attack':
        data_to_use = df[df['threat_type'] != 'valid']
    elif label in possible_attacks:
        data_to_use = df[df['threat_type'] == label]
    else:
        data_to_use = df[df['location'] == label]
    return dash_table.DataTable(
            id = 'data_table',
            columns=[configure_columns(i) for i in data_to_use.drop(['id', 'log_id', 'request'], axis = 1).columns],
            data = data_to_use.drop(['id', 'log_id', 'request'], axis = 1).to_dict('records'),
            style_cell={
                'overflow': 'hidden',
                'textOverflow': 'ellipsis',
                'maxWidth': 0,
            },
            tooltip_data=[
                {
                    'request': {'value': str(row['request']), 'type':'markdown'}
                } for row in data_to_use.to_dict('records')
            ],
            tooltip_duration = None,
            #style_table={'overflowX': 'auto'},
            page_action="native",
            page_current= 0,
            page_size= 10,
            filter_action = 'native',
            cell_selectable = False
        )


############################################################################################################
external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']
server = Flask(__name__)
app = dash.Dash(__name__, external_stylesheets=external_stylesheets, server=server)

app.layout = html.Div(children=[
    html.Div(children = [
        html.H1(children='WAF Dashboard'),

        html.Div(children='''
            Dashboard for attack classification from the ML model
        ''')
    ]),
    html.Div(id = 'graph', children=[
        dcc.Graph(
            id='example-graph1',
            figure=make_subplots(rows = 1, cols = 3, specs=[[{'type':'domain'}, {'type':'domain'}, {'type':'domain'}]])
        )
    ]),
    html.Div(id = 'table-data', style = {'width': '100%'}),
    html.Div(id ='reset-button-div', children=[
        html.Button('Clear filters', id='reset-button', n_clicks=0)
    ])
])


@app.callback(
    [Output('table-data', 'children'),
    Output('graph', 'children')],
    [Input('example-graph1', 'clickData'),
    Input('reset-button', 'n_clicks')])
def display_hover_data(hover_data, n_clicks):
    ctx = dash.callback_context

    if not ctx.triggered:
        component_id = None
    else:
        component_id = ctx.triggered[0]['prop_id'].split('.')[0]
    # print(component_id)
    db = DBController()
    raw_data = db.read_all()
    db.close()
    
    label = None
    if component_id == 'example-graph1':
        if hover_data is not None:
            label = hover_data['points'][0]['label']
    return generate_table(raw_data, label), generate_figure(raw_data)


@server.route('/')
def index():
    return app.index()


@server.route('/review/<int:request_id>', methods = ['GET'])
def review_request(request_id):
    root_dir = os.path.abspath(os.curdir)
    log_dir = os.path.join(root_dir, 'logs/requests')
    if not os.path.isdir(log_dir):
        log_dir = os.path.join(root_dir, '../logs/requests')
    with open(f"{log_dir}/{str(request_id)}.json", 'r') as f:
        request = json.dumps(json.load(f), indent=4)
    db = DBController()
    log, data = db.read_request(int(request_id))
    db.close()
    return render_template('request.html', id=str(request_id), 
                           request=request, num_attacks=len(data), attacks=data, log=log)


if __name__ == '__main__':
    app.run_server(debug=True)
    