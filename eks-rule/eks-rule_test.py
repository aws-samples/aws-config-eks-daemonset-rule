"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import sys
import unittest
from unittest.mock import MagicMock, patch
import botocore
from datetime import datetime
import copy
import json

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EKS::Cluster'

#############
# Main Code #
#############

STS_CLIENT_MOCK = MagicMock()
CONFIG_CLIENT_MOCK = MagicMock()
EKS_CLIENT_MOCK = MagicMock()
SESSION_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
           return CONFIG_CLIENT_MOCK
        if client_name == 'eks':
            return EKS_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

    def session():
        return SESSION_MOCK

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('eks-rule')

list_clusters = {
    'clusters': [
        'test-cluster',
    ],
    'nextToken': 'string'
}

class TestHelperMixin:

    def _run_test(self, list_clusters, expected_result):
        list_clusters_mock = MagicMock()
        list_clusters_mock.paginate = MagicMock(
            return_value=list_clusters)

        EKS_CLIENT_MOCK.get_paginator = MagicMock(
            return_value=list_clusters_mock)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})

        assert_successful_evaluation(
            self, response, expected_result, len(response))



class ComplianceTest(unittest.TestCase, TestHelperMixin):

    inner_config = '{"spec": {"template": {"spec": {"containers": [{"env": [{"name": "AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG","value": "true"},{"name": "AWS_VPC_K8S_CNI_LOGLEVEL","value": "DEBUG"}] }]}}}}'
    daemon_set_config = {
        "metadata": {
            "annotations": {
                "kubectl.kubernetes.io/last-applied-configuration": inner_config
            }
        }
    }

    def test_AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG_env_variable_set_to_true(self):
        RULE.daemonsets_resp = MagicMock(return_value=self.daemon_set_config)
        test_cases = [
            dict(
                message='AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG is set to true',
                list_clusters =[list_clusters],
                expected_response=[build_expected_response(compliance_type='COMPLIANT',
                                                           compliance_resource_id='test-cluster',
                                                           compliance_resource_type=DEFAULT_RESOURCE_TYPE)],
            )
        ]

        for test_data in test_cases:
            with self.subTest(test_data['message'], test_data=test_data):
                self._run_test(test_data['list_clusters'],
                               test_data['expected_response'])

class NonComplianceTest(unittest.TestCase, TestHelperMixin):
    inner_config = '{"spec": {"template": {"spec": {"containers": [{"env": [{"name": "AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG","value": "false"},{"name": "AWS_VPC_K8S_CNI_LOGLEVEL","value": "DEBUG"}] }]}}}}'
    daemon_set_config = {
        "metadata": {
            "annotations": {
                "kubectl.kubernetes.io/last-applied-configuration": inner_config
            }
        }
    }

    def test_AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG_env_variable_set_to_false(self):
        RULE.daemonsets_resp = MagicMock(return_value=self.daemon_set_config)
        test_cases = [
            dict(
                message='AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG is set to false',
                list_clusters =[list_clusters],
                expected_response=[build_expected_response(compliance_type='NON_COMPLIANT',
                                                           compliance_resource_id='test-cluster',
                                                           compliance_resource_type=DEFAULT_RESOURCE_TYPE,
                                                           annotation='AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG environment variable must be set to true')],
            )
        ]

        for test_data in test_cases:
            with self.subTest(test_data['message'], test_data=test_data):
                self._run_test(test_data['list_clusters'],
                               test_data['expected_response'])

####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_lambda_scheduled_event(rule_parameters=None):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_expected_response(compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    if not annotation:
        return {
            'ComplianceType': compliance_type,
            'ComplianceResourceId': compliance_resource_id,
            'ComplianceResourceType': compliance_resource_type
            }
    return {
        'ComplianceType': compliance_type,
        'ComplianceResourceId': compliance_resource_id,
        'ComplianceResourceType': compliance_resource_type,
        'Annotation': annotation
        }

def assert_successful_evaluation(test_class, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        test_class.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        test_class.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        test_class.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        test_class.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            test_class.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        test_class.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            test_class.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            test_class.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            test_class.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            test_class.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                test_class.assertEquals(response_expected['Annotation'], response[i]['Annotation'])

def assert_customer_error_response(test_class, response, customer_error_code=None, customer_error_message=None):
    if customer_error_code:
        test_class.assertEqual(customer_error_code, response['customerErrorCode'])
    if customer_error_message:
        test_class.assertEqual(customer_error_message, response['customerErrorMessage'])
    test_class.assertTrue(response['customerErrorCode'])
    test_class.assertTrue(response['customerErrorMessage'])
    if "internalErrorMessage" in response:
        test_class.assertTrue(response['internalErrorMessage'])
    if "internalErrorDetails" in response:
        test_class.assertTrue(response['internalErrorDetails'])

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    STS_CLIENT_MOCK.reset_mock(return_value=True)
    STS_CLIENT_MOCK.assume_role = MagicMock(return_value=assume_role_response)

##################
# Common Testing #
##################

class TestStsErrors(unittest.TestCase):

    def test_sts_unknown_error(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
