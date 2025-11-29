Modern BinaryAlert (AWS CDK + Docker Edition)
=============================================

.. image:: docs/images/logo.png
  :align: center
  :scale: 75%
  :alt: BinaryAlert Logo

Serverless, real-time malware detection using YARA, modernized for 2025 with AWS CDK and Container support.

Architecture Overview
---------------------

.. image:: docs/images/architecture.png
  :align: center
  :scale: 75%
  :alt: Architecture

* **S3 Bucket**: Binaries uploaded here trigger the analysis pipeline.
* **SQS Queue**: Buffers analysis requests to decouple ingestion from processing.
* **Analyzer Lambda**: A Docker-based Python 3.12 Lambda function that scans files using the YARA engine. Built for ``linux/amd64`` to support legacy binaries.
* **Downloader Lambda**: Fetches samples directly from CrowdStrike EDR for analysis.
* **DynamoDB**: Stores YARA match results and analysis metadata.
* **SNS**: Publishes alerts when malware is detected.

Prerequisites
-------------

* **AWS CLI**: Installed and configured with appropriate credentials.
* **AWS CDK CLI**: Installed globally via Node.js (``npm install -g aws-cdk``).
* **Docker Desktop**: Must be running to build the Lambda container images.
* **Python 3.12+**: Required for the CDK app and local development.

Installation & Deployment
-------------------------

1. **Create Virtual Environment**

   .. code-block:: bash

       python3 -m venv .venv
       source .venv/bin/activate

2. **Install Dependencies**

   .. code-block:: bash

       pip install -r requirements.txt

3. **Bootstrap CDK (First Time Only)**

   If you haven't used CDK in this AWS region before:

   .. code-block:: bash

       cdk bootstrap

4. **Deploy**

   Deploy the stack to your AWS account:

   .. code-block:: bash

       cdk deploy

Configuration
-------------

* **YARA Rules**: Place your ``.yara`` rules in the ``rules/`` directory. They are automatically compiled and baked into the Docker image during the build process.

Credits
-------

Based on the original **BinaryAlert** concept and logic by **Airbnb Security**.
Refactored and modernized for AWS CDK and Docker.
