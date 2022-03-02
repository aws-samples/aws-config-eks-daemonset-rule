# aws-config-eks-daemonset-rule

## Introduction

`aws-config-eks-daemonset-rule` is an example aws config project that demonstrates how to write a rule to test the daemonset of and EKS cluster. This project includes EKS config rule with a unit test case for the rule. 


Conscidering that this rule is testing a config that is external to your AWS env the rule will need to be triggered periodically rather than triggering based on a change. The rule will work by making an API request to the kubernestes cluster end point to fetch the daemonset. This endpoint can be accessed from the kubernetes cluster. You should have a cluster deployed prior to testing your rule.


## Instructions

1. Ensure that you have python and pip installed

2. Ensure that you have the AWS CLI configured

3. Install rdk

```
 $ pip install rdk
```

4. Deploy the rules

```
$ cd eks-rule
$ rdk deploy eks-rule
```

## Test rule
```
$ cd eks-rule
$ rdk test-local eks-rule
```

## Security
See CONTRIBUTING for more information.

## License
This library is licensed under the MIT-0 License. See the LICENSE file.

