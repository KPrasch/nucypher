import json
import os
import re
from base64 import b64decode

import pytest
import responses
from pytest_dash import wait_for
from pytest_dash.application_runners import import_app
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from umbral.keys import UmbralPrivateKey

from nucypher.crypto.kits import UmbralMessageKit
from nucypher.crypto.powers import DecryptingPower
from nucypher.utilities.sandbox.policy import generate_random_label

from examples.heartbeat_rest_ui.app import POLICY_INFO_FILE

ALICE_URL = "http://localhost:8151"
ENRICO_URL = "http://localhost:5151"
BOB_URL = "http://localhost:11151"


@pytest.fixture(scope='module')
def dash_app():
    dash_app = import_app('examples.heartbeat_rest_ui.char_control_heartbeat', application_name='app')
    yield dash_app


@pytest.fixture(scope='function')
def dash_driver(dash_threaded, dash_app):
    dash_threaded(dash_app)
    dash_driver = dash_threaded.driver
    home_page = dash_driver.current_window_handle

    yield dash_driver  # provide the fixture value

    # close all windows except for home page
    open_handles = dash_driver.window_handles
    for handle in open_handles:
        if handle != home_page:
            dash_driver.switch_to.window(handle)
            dash_driver.close()

    dash_driver.switch_to.window(home_page)


class wait_for_non_empty_text(object):
    def __init__(self, locator):
        self.locator = locator

    def __call__(self, driver):
        element = driver.find_element(*self.locator)
        if element.text != '':
            return element
        else:
            return False


@responses.activate
def test_alicia_derive_policy_key_failed(dash_driver):
    bad_status_code = 400

    ##########################
    # setup endpoint responses
    ##########################
    # '/derive_policy_encrypting_key'
    def derive_key_callback(request):
        return (bad_status_code,
                request.headers,
                json.dumps({'message': 'execution failed'}))

    responses.add_callback(responses.POST,
                           url=re.compile(f'{ALICE_URL}/derive_policy_encrypting_key/.*', re.IGNORECASE),
                           callback=derive_key_callback,
                           content_type='application/json')
    ##########################

    # open alicia tab
    alicia_link = dash_driver.find_element_by_link_text('ALICIA')
    alicia_link.click()

    ######################
    # switch to alicia tab
    ######################
    base_handle = dash_driver.current_window_handle

    dash_driver.switch_to.window('_alicia')

    # derive label and policy key
    create_policy_button = wait_for.wait_for_element_by_css_selector(dash_driver, '#create-policy-button')
    create_policy_button.click()

    # wait for response
    policy_key_element = WebDriverWait(dash_driver, 10).until(
        wait_for_non_empty_text((By.ID, 'policy-enc-key'))
    )
    policy_label_element = dash_driver.find_element_by_id('policy-label')

    # test results
    assert 1 == len(responses.calls)

    request_url = responses.calls[0].request.url
    assert 'derive_policy_encrypting_key' in request_url

    policy_label = request_url[request_url.rfind('/')+1:]
    assert policy_label == policy_label_element.text

    assert bad_status_code == responses.calls[0].response.status_code
    assert str(bad_status_code) in policy_key_element.text
    assert '> ERROR' in policy_key_element.text


@responses.activate
def test_alicia_grant_failed(dash_driver,
                             alice_control_test_client,
                             federated_bob):
    bad_status_code = 500

    ##########################
    # setup endpoint responses
    ##########################
    def derive_key_callback(request):
        label = request.url[request.url.rfind('/')+1:]
        derive_response = alice_control_test_client.post(f'/derive_policy_encrypting_key/{label}')
        return (derive_response.status_code,
                derive_response.headers,
                derive_response.data)

    responses.add_callback(responses.POST,
                           url=re.compile(f'{ALICE_URL}/derive_policy_encrypting_key/.*', re.IGNORECASE),
                           callback=derive_key_callback,
                           content_type='application/json')

    # '/grant'
    def grant_callback(request):
        return (bad_status_code,
                request.headers,
                json.dumps({'message': 'execution failed'}))

    responses.add_callback(responses.PUT,
                           url=re.compile(f'{ALICE_URL}/grant', re.IGNORECASE),
                           callback=grant_callback,
                           content_type='application/json')
    ##########################

    # open alicia tab
    alicia_link = dash_driver.find_element_by_link_text('ALICIA')
    alicia_link.click()

    ######################
    # switch to alicia tab
    ######################
    dash_driver.switch_to.window('_alicia')

    # Grant can only occur with a policy key previously derived
    # derive label and policy key
    create_policy_button = wait_for.wait_for_element_by_css_selector(dash_driver, '#create-policy-button')
    create_policy_button.click()

    # wait for response
    WebDriverWait(dash_driver, 10).until(
        wait_for_non_empty_text((By.ID, 'policy-enc-key'))
    )

    # grant access to bob
    m_threshold_element = dash_driver.find_element_by_id('m-value')
    m_threshold_element.send_keys(Keys.ARROW_UP)  # 1 -> 2

    n_shares_element = dash_driver.find_element_by_id('n-value')
    n_shares_element.send_keys(Keys.ARROW_UP)  # 1 -> 2
    n_shares_element.send_keys(Keys.ARROW_UP)  # 2 -> 3

    bob_encrypting_key_hex = bytes(federated_bob.public_keys(DecryptingPower)).hex()
    bob_signing_key_hex = bytes(federated_bob.stamp).hex()

    bob_signing_key_element = dash_driver.find_element_by_id('recipient-sig-key-grant')
    bob_signing_key_element.clear()
    bob_signing_key_element.send_keys(bob_signing_key_hex)

    bob_encrypting_key_element = dash_driver.find_element_by_id('recipient-enc-key-grant')
    bob_signing_key_element.clear()
    bob_encrypting_key_element.send_keys(bob_encrypting_key_hex)

    grant_button = dash_driver.find_element_by_id('grant-button')
    grant_button.click()

    # wait for response
    grant_response_element = WebDriverWait(dash_driver, 10).until(
        wait_for_non_empty_text((By.ID, 'grant-response'))
    )

    # test results
    assert 2 == len(responses.calls)

    request_url = responses.calls[1].request.url
    assert 'grant' in request_url

    assert bad_status_code == responses.calls[1].response.status_code
    assert str(bad_status_code) in grant_response_element.text
    assert '> ERROR' in grant_response_element.text


@responses.activate
def test_enrico_encrypt_data_failed(dash_driver):
    bad_status_code = 404

    ##########################
    # setup endpoint responses
    ##########################
    # '/encrypt_message'
    def encrypt_message_callback(request):
        return (bad_status_code,
                request.headers,
                json.dumps({'message': 'execution failed'}))

    responses.add_callback(responses.POST,
                           url=re.compile(f'{ENRICO_URL}/encrypt_message', re.IGNORECASE),
                           callback=encrypt_message_callback,
                           content_type='application/json')
    ##########################

    # open enrico tab
    enrico_link = dash_driver.find_element_by_link_text('ENRICO (HEART_MONITOR)')
    enrico_link.click()

    ######################
    # switch to enrico tab
    ######################
    dash_driver.switch_to.window('_enrico')

    start_monitoring_button = wait_for.wait_for_element_by_css_selector(dash_driver, "#generate-button")
    start_monitoring_button.click()

    # wait for response
    last_heartbeat_element = WebDriverWait(dash_driver, 5).until(
        wait_for_non_empty_text((By.ID, 'cached-last-heartbeat'))
    )

    # test results
    assert 1 <= len(responses.calls)  # derive then at least one encrypt message
    request_url = responses.calls[0].request.url
    assert 'encrypt_message' in request_url

    assert bad_status_code == responses.calls[0].response.status_code
    assert 'WARNING' in last_heartbeat_element.text
    assert str(bad_status_code) in last_heartbeat_element.text


def test_bob_no_policy_file_failed(dash_driver,
                                   federated_bob):
    ######################
    # switch to bob tab
    ######################
    # open bob tab
    bob_link = dash_driver.find_element_by_link_text('BOB')
    bob_link.click()

    dash_driver.switch_to.window('_bob')

    read_heartbeats_button = wait_for.wait_for_element_by_css_selector(dash_driver, "#read-button")

    bob_port = 11151
    bob_port_element = dash_driver.find_element_by_id('bob-port')
    bob_port_element.clear()
    bob_port_element.send_keys(bob_port)

    bob_encrypting_key_hex = bytes(federated_bob.public_keys(DecryptingPower)).hex()
    bob_enc_key_element = dash_driver.find_element_by_id('bob-enc-key')
    bob_enc_key_element.clear()
    bob_enc_key_element.send_keys(bob_encrypting_key_hex)

    read_heartbeats_button.click()

    # wait for response
    heartbeats_element = WebDriverWait(dash_driver, 5).until(
        wait_for_non_empty_text((By.ID, 'heartbeats'))
    )

    assert "WARNING" in heartbeats_element.text
    assert "not been granted" in heartbeats_element.text


@responses.activate
def test_bob_join_policy_failed(dash_driver,
                                federated_alice,
                                federated_bob):
    ##########################
    # setup endpoint responses
    ##########################
    bad_status_code = 500

    # '/join_policy'
    def join_policy_callback(request):
        return (bad_status_code,
                request.headers,
                json.dumps({'message': 'execution failed'}))

    responses.add_callback(responses.POST,
                           url=re.compile(f'{BOB_URL}/join_policy', re.IGNORECASE),
                           callback=join_policy_callback,
                           content_type='application/json')
    ##########################

    # write fake policy file
    policy_label = f'heart-data-{os.urandom(4).hex()}'
    policy_info = {
        "policy_encrypting_key": UmbralPrivateKey.gen_key().get_pubkey().to_bytes().hex(),
        "alice_verifying_key": bytes(federated_alice.stamp).hex(),
        "label": policy_label,
    }

    bob_encrypting_key_hex = bytes(federated_bob.public_keys(DecryptingPower)).hex()
    with open(POLICY_INFO_FILE.format(bob_encrypting_key_hex), 'w') as f:
        json.dump(policy_info, f)

    ######################
    # switch to bob tab
    ######################
    # open bob tab
    bob_link = dash_driver.find_element_by_link_text('BOB')
    bob_link.click()

    dash_driver.switch_to.window('_bob')

    read_heartbeats_button = wait_for.wait_for_element_by_css_selector(dash_driver, "#read-button")

    bob_port = 11151
    bob_port_element = dash_driver.find_element_by_id('bob-port')
    bob_port_element.clear()
    bob_port_element.send_keys(bob_port)

    bob_encrypting_key_hex = bytes(federated_bob.public_keys(DecryptingPower)).hex()
    bob_enc_key_element = dash_driver.find_element_by_id('bob-enc-key')
    bob_enc_key_element.clear()
    bob_enc_key_element.send_keys(bob_encrypting_key_hex)

    read_heartbeats_button.click()

    # wait for response
    heartbeats_element = WebDriverWait(dash_driver, 5).until(
        wait_for_non_empty_text((By.ID, 'heartbeats'))
    )

    assert 1 <= len(responses.calls)

    request_url = responses.calls[0].request.url
    assert 'join_policy' in request_url
    assert str(bob_port) in request_url

    assert bad_status_code == responses.calls[0].response.status_code
    assert 'WARNING' in heartbeats_element.text
    assert 'not been granted' in heartbeats_element.text


@responses.activate
def test_heartbeat_rest_ui_demo_lifecycle(dash_driver,
                                          alice_control_test_client,
                                          enrico_control_test_client,
                                          federated_bob):
    ##########################
    # setup endpoint responses
    ##########################
    # '/derive_policy_encrypting_key'
    def derive_key_callback(request):
        label = request.url[request.url.rfind('/')+1:]
        derive_response = alice_control_test_client.post(f'/derive_policy_encrypting_key/{label}')
        return (derive_response.status_code,
                derive_response.headers,
                derive_response.data)

    responses.add_callback(responses.POST,
                           url=re.compile(f'{ALICE_URL}/derive_policy_encrypting_key/.*', re.IGNORECASE),
                           callback=derive_key_callback,
                           content_type='application/json')

    # '/encrypt_message'
    def encrypt_message_callback(request):
        encrypt_response = enrico_control_test_client.post('/encrypt_message', data=request.body)
        return (encrypt_response.status_code,
                encrypt_response.headers,
                encrypt_response.data)

    responses.add_callback(responses.POST,
                           url=re.compile(f'{ENRICO_URL}/encrypt_message', re.IGNORECASE),
                           callback=encrypt_message_callback,
                           content_type='application/json')

    # '/grant'
    def grant_callback(request):
        grant_response = alice_control_test_client.put('/grant', data=request.body)
        return (grant_response.status_code,
                grant_response.headers,
                grant_response.data)

    responses.add_callback(responses.PUT,
                           url=re.compile(f'{ALICE_URL}/grant', re.IGNORECASE),
                           callback=grant_callback,
                           content_type='application/json')

    ##########################

    home_page = dash_driver.current_window_handle

    # open alicia tab
    alicia_link = dash_driver.find_element_by_link_text('ALICIA')
    alicia_link.click()

    dash_driver.switch_to.window(home_page)

    # open enrico tab
    enrico_link = dash_driver.find_element_by_link_text('ENRICO (HEART_MONITOR)')
    enrico_link.click()

    dash_driver.switch_to.window(home_page)

    # open bob tab
    bob_link = dash_driver.find_element_by_link_text('BOB')
    bob_link.click()

    ######################
    # switch to alicia tab
    ######################
    dash_driver.switch_to.window('_alicia')

    # derive label and policy key
    create_policy_button = wait_for.wait_for_element_by_css_selector(dash_driver, '#create-policy-button')
    create_policy_button.click()

    # wait for response
    policy_key_element = WebDriverWait(dash_driver, 10).until(
        wait_for_non_empty_text((By.ID, 'policy-enc-key'))
    )
    policy_label_element = dash_driver.find_element_by_id('policy-label')

    # test results
    assert 1 == len(responses.calls)

    request_url = responses.calls[0].request.url
    assert 'derive_policy_encrypting_key' in request_url

    policy_label = request_url[request_url.rfind('/')+1:]
    assert policy_label == policy_label_element.text

    assert 200 == responses.calls[0].response.status_code
    response_json = responses.calls[0].response.text
    response_data = json.loads(response_json)
    derived_policy_key = response_data['result']['policy_encrypting_key']
    assert derived_policy_key == policy_key_element.text

    ######################
    # switch to enrico tab
    ######################
    dash_driver.switch_to.window('_enrico')

    start_monitoring_button = wait_for.wait_for_element_by_css_selector(dash_driver, "#generate-button")
    start_monitoring_button.click()

    # wait for response
    last_heartbeat_element = WebDriverWait(dash_driver, 5).until(
        wait_for_non_empty_text((By.ID, 'cached-last-heartbeat'))
    )
    # verify that actual number
    assert int(last_heartbeat_element.text)

    # test results
    assert 2 <= len(responses.calls)  # derive then at least one encrypt message
    request_url = responses.calls[1].request.url
    assert 'encrypt_message' in request_url

    assert 200 == responses.calls[1].response.status_code
    response_json = responses.calls[1].response.text
    print(response_json)
    response_data = json.loads(response_json)
    message_kit = response_data['result']['message_kit']
    assert UmbralMessageKit.from_bytes(b64decode(message_kit))

    ######################
    # switch to alicia tab
    ######################
    dash_driver.switch_to.window('_alicia')

    # grant access to bob
    m_threshold_element = dash_driver.find_element_by_id('m-value')
    m_threshold_element.send_keys(Keys.ARROW_UP)  # 1 -> 2

    n_shares_element = dash_driver.find_element_by_id('n-value')
    n_shares_element.send_keys(Keys.ARROW_UP)  # 1 -> 2
    n_shares_element.send_keys(Keys.ARROW_UP)  # 2 -> 3

    bob_encrypting_key_hex = bytes(federated_bob.public_keys(DecryptingPower)).hex()
    bob_signing_key_hex = bytes(federated_bob.stamp).hex()

    bob_signing_key_element = dash_driver.find_element_by_id('recipient-sig-key-grant')
    bob_signing_key_element.clear()
    bob_signing_key_element.send_keys(bob_signing_key_hex)

    bob_encrypting_key_element = dash_driver.find_element_by_id('recipient-enc-key-grant')
    bob_signing_key_element.clear()
    bob_encrypting_key_element.send_keys(bob_encrypting_key_hex)

    grant_button_element = dash_driver.find_element_by_id('grant-button')
    grant_button_element.click()

    # wait for response
    grant_response_element = WebDriverWait(dash_driver, 10).until(
        wait_for_non_empty_text((By.ID, 'grant-response'))
    )

    assert "granted to recipient" in grant_response_element.text
    assert policy_label in grant_response_element.text
    assert bob_encrypting_key_hex in grant_response_element.text
    assert "> ERROR" not in grant_response_element.text
    assert "status code" not in grant_response_element.text
