#!/bin/sh
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
TITLE=RemoveMembersTest
BENCH="RemoveMembersTest"
BATCH_SIZE="1 10" # 10 50 100 500
MEMBERS_CNT="50 100 150" # 1 10 100 500 1000 5000 10000
RUNTIME=60
FIXS="Oak-Segment-Tar"
THREADS="1" #"1,2,4,8,10,15,20,50"
PROFILE=false

LOG=$TITLE"_$(date +'%Y%m%d_%H%M%S').csv"
echo "Benchmarks: $BENCH" > $LOG
echo "Fixture: $FIXS" >> $LOG
echo "Runtime: $RUNTIME" >> $LOG
echo "Concurrency: $THREADS" >> $LOG
echo "Profiling: $PROFILE" >> $LOG

echo "Batch Size: $BATCH_SIZE" >> $LOG
echo "Import Behavior: $IMPORT_BEHAVIORS" >> $LOG
echo "Number of Members: $MEMBERS_CNT" >> $LOG

echo "--------------------------------------" >> $LOG

for bm in $BENCH
    do
    for batchsize in $BATCH_SIZE
        do
        for noMembers in $MEMBERS_CNT
        do
            echo "Executing benchmarks with $noMembers members with batchsize $batchsize on $importBehavior" | tee -a $LOG
            echo "-----------------------------------------------------------" | tee -a $LOG
            rm -rf target/Jackrabbit-* target/Oak-Tar-*
            cmd="java -Xmx2048m -Druntime=$RUNTIME -jar target/oak-benchmarks-*-SNAPSHOT.jar benchmark --batchSize $batchsize --numberOfUsers $noMembers --csvFile $LOG --concurrency $THREADS --report false $bm $FIXS"
            echo $cmd
            $cmd

            rm -rf target/Jackrabbit-* target/Oak-Tar-*
            cmd2="java -Xmx2048m -DGroupImpl.useNew=true -Druntime=$RUNTIME -jar target/oak-benchmarks-*-SNAPSHOT.jar benchmark --batchSize $batchsize --numberOfUsers $noMembers --csvFile $LOG --concurrency $THREADS --report false $bm $FIXS"
            echo $cmd2
            $cmd2

        done
    done
done
echo "-----------------------------------------"
echo "Benchmark completed. see $LOG for details:"
cat $LOG
