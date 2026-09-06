#!/usr/bin/env python3
"""Helper script to tag or untag AWS resources for Bill Shock Guard protection testing.

Usage:
    python scripts/tag_resource.py --resource-id <id> --region <region> [--remove]
"""

import argparse
import sys

import boto3


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tag or untag resources with bsg:keep protection tag."
    )
    parser.add_argument(
        "--resource-id",
        required=True,
        help="AWS resource ID (e.g. i-12345, vol-12345, eipalloc-12345)",
    )
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--tag-key", default="bsg:keep", help="Protect tag key (default: bsg:keep)")
    parser.add_argument("--tag-value", default="true", help="Protect tag value (default: true)")
    parser.add_argument(
        "--remove", action="store_true", help="Remove the protection tag instead of adding it"
    )

    args = parser.parse_args()

    ec2 = boto3.client("ec2", region_name=args.region)

    if args.remove:
        print(f"Removing tag '{args.tag_key}' from {args.resource_id} in {args.region}...")
        try:
            ec2.delete_tags(
                Resources=[args.resource_id],
                Tags=[{"Key": args.tag_key}],
            )
            print("Tag removed successfully.")
        except Exception as exc:
            print(f"Error removing tag: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        msg = (
            f"Applying tag '{args.tag_key}={args.tag_value}' to "
            f"{args.resource_id} in {args.region}..."
        )
        print(msg)
        try:
            ec2.create_tags(
                Resources=[args.resource_id],
                Tags=[{"Key": args.tag_key, "Value": args.tag_value}],
            )
            print("Tag applied successfully.")
        except Exception as exc:
            print(f"Error applying tag: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
