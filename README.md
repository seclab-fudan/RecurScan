# Source Code and Dataset of RecurScan

This document will introduce the setup and usage of RecurScan.

## RecurScan Setup

RecurScan consists of two parts: Neo4j databases and Python code. This section will guide you to set up each of them respectively.

### Step1: Setting the Environment

**1) Install the Dependencies**

```shell
-> % pip3 install -r requirements.txt
```

**2) Install Neo4j**
Download and install Neo4j (available at https://neo4j.com/download/).

### Step2: Preparing Neo4j databases

**1) Construct Neo4j Databases**

To support the analysis of RecurScan, you need to construct the Code Property Graphs for known vulnerability patches and the target applications. Then import them into Neo4j.

You can follow the instructions at `https://github.com/malteskoruppa/phpjoern` to construct the code property graph databases.

After constructing Neo4j Databases, run the following command to move them to `databases/`:

```shell
mv /path/to/neo4j databases/
```

**2) Configure Neo4j connectors**

Next, you should edit the configuration files of Neo4j and RecurScan to ensure that RecurScan can properly connect to the databases.

For Neo4j, you can edit its configuration file (usually in `/path/to/neo4j/conf/neo4j.conf`). Please pay attention to these statements:

```
dbms.connector.http.listen_address=:PORT_A
dbms.connector.bolt.listen_address=:PORT_B
```

For RecurScan, you can edit the `config/neo4j.json` file to set up its connections to Neo4j. The content look like the following:

```json
{
  // ...
  "database-name": {
    "NEO4J_HOST": "localhost",
    "NEO4J_PORT": PORT_A,
    "NEO4J_USERNAME": "neo4j",
    "NEO4J_PASSWORD": "neo4j",
    "NEO4J_DATABASE": "neo4j",
    "NEO4J_PROTOCOL": "http"
  }
  //...
}
```

> Note that the listening ports of the Neo4j (e.g., PORT_A and PORT_B) should not be occupied and keep consistent with the RecurScan configuration.

### Step3: Running RecurScan

First, you can generate the known vulnerability signature with the following command:

```shell
python signature_generator.py
```

Then, you can detect recurring vulnerabilities in a target application by running RecurScan:

```shell
python rcs_main.py <target_application>
```

## Dataset

The dataset for the evaluation is provided in the `dataset/dataset.json`, where each item corresponds to a CMS name and GitHub URL.