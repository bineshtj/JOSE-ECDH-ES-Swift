#!/usr/bin/env bash

cd $(dirname $0)/../

pod trunk push ECDHESSwift.podspec --verbose --allow-warnings --swift-version=4.2
