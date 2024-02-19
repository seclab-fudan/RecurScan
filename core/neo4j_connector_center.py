import json

from config import NEO4J_CONFIGURE_MAP_PATH


class Neo4jConnectorCenter(object):
    @staticmethod
    def from_map(map_key):
        config_map = json.load(open(NEO4J_CONFIGURE_MAP_PATH, 'r'))
        if map_key not in config_map.keys():
            raise KeyError(f"fail to get map key {map_key}")
        else:
            return config_map[map_key]
