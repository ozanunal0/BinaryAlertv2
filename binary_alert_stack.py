from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_s3 as s3,
    aws_sqs as sqs,
    aws_lambda as _lambda,
    aws_dynamodb as dynamodb,
    aws_s3_notifications as s3_notifications,
    aws_iam as iam,
    aws_sns as sns,               # <-- Yeni
    aws_sns_subscriptions as subs,# <-- Yeni
    aws_ecr_assets as ecr_assets,
)
from constructs import Construct

class BinaryAlertStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # 1. SNS Topic
        alert_topic = sns.Topic(self, "YaraMatchTopic",
            display_name="BinaryAlert - Malware Found"
        )
        
        alert_topic.add_subscription(subs.EmailSubscription(""))

        # 2. DynamoDB Table
        table = dynamodb.Table(
            self, "YaraMatchesTable",
            table_name="YaraMatches",
            partition_key=dynamodb.Attribute(name="SHA256", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="AnalyzerVersion", type=dynamodb.AttributeType.NUMBER),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY
        )

        # 3. SQS Queue
        queue = sqs.Queue(
            self, "BinaryAlertQueue",
            visibility_timeout=Duration.seconds(120),
            retention_period=Duration.days(14)
        )

        # 4. S3 Bucket
        bucket = s3.Bucket(
            self, "BinaryAlertBucket",
            versioned=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )
        bucket.add_event_notification(s3.EventType.OBJECT_CREATED, s3_notifications.SqsDestination(queue))

        # 5. Lambda Function
        analyzer_function = _lambda.DockerImageFunction(
            self, "AnalyzerFunction",
            code=_lambda.DockerImageCode.from_image_asset(
                ".",
                platform=ecr_assets.Platform.LINUX_AMD64
            ),
            architecture=_lambda.Architecture.X86_64,
            memory_size=2048,
            timeout=Duration.seconds(60),
            environment={
                "YARA_MATCHES_DYNAMO_TABLE_NAME": table.table_name,
                "YARA_ALERTS_SNS_TOPIC_ARN": alert_topic.topic_arn,
                "NO_MATCHES_SNS_TOPIC_ARN": "",
                "LD_LIBRARY_PATH": "/usr/lib64:$LD_LIBRARY_PATH"
            },
        )
        
        from aws_cdk import aws_lambda_event_sources
        analyzer_function.add_event_source(aws_lambda_event_sources.SqsEventSource(queue))

        bucket.grant_read(analyzer_function)
        table.grant_read_write_data(analyzer_function)
        
        alert_topic.grant_publish(analyzer_function)
        
        analyzer_function.add_to_role_policy(iam.PolicyStatement(
            actions=["cloudwatch:PutMetricData"],
            resources=["*"]
        ))