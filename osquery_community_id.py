import osquery
import communityid
import json

@osquery.register_plugin
class MyTablePlugin(osquery.TablePlugin):
    def name(self):
        """
        Input: self
        Output: Returns the name of the  table
        """
        return "community_id"

    def columns(self):
        """
        Input: self
        Output: List of columns for the table and there type
        """
        return [
            osquery.TableColumn(name="src_ip", type=osquery.STRING),
            osquery.TableColumn(name="src_port", type=osquery.INTEGER),
            osquery.TableColumn(name="dst_ip", type=osquery.STRING),
            osquery.TableColumn(name="dst_port", type=osquery.INTEGER),
            osquery.TableColumn(name="protocol", type=osquery.INTEGER),
            osquery.TableColumn(name="community_id", type=osquery.STRING)
        ]


    def generate(self, context):
        """
        Input: Context contains all the query values passed to Osquery
        Output: Returns a list which contains a dictonary which contains all
        the values passed in by context and the calculated CommunityID hash
        for the network connection
        """

        # Convvert context string into a dicotnary with JSON module
        query_data = []
        temp = json.loads(context.replace("'", "\""))
        context_dict = json.loads(temp)

        # Extract values from dictonary
        src_ip = dst_ip = str()
        src_port = dst_port = protocol= int()
        for constraint in context_dict['constraints']:
            if constraint['name'] == 'src_ip' and len(constraint['list']) > 0:
                src_ip = constraint['list'][0]['expr']
            elif constraint['name'] == 'src_port'  and len(constraint['list']) > 0:
                src_port = int(constraint['list'][0]['expr'])
            elif constraint['name'] == 'dst_ip' and len(constraint['list']) > 0:
                dst_ip = constraint['list'][0]['expr']
            elif constraint['name'] == 'dst_port' and len(constraint['list']) > 0:
                dst_port = int(constraint['list'][0]['expr'])
            elif constraint['name'] == 'protocol' and len(constraint['list']) > 0:
                protocol = int(constraint['list'][0]['expr'])
            else:
                continue

        # Init CommunityID  object
        cid = communityid.CommunityID()
        community_id = str()

        # Calculate community ID
        # Protocol
        # TCP: 6
        # UDP: 17
        # https://en.wikipedia.org/wiki/IPv4 
        if protocol == 6:
            tpl = communityid.FlowTuple.make_tcp(src_ip, dst_ip, src_port, dst_port)
            community_id = cid.calc(tpl)
        elif protocol == 17:
            tpl = communityid.FlowTuple.make_udp(src_ip, dst_ip, src_port, dst_port)
            community_id = cid.calc(tpl)
        else:
            print ( f"[-] - {datetime.now()} - Protocol not supported - \
                src_ip: {src_ip} - \
                src_port:{src_port} - \
                dst_ip: {dst_ip} - \
                dst_port:{dst_port} - \
                Protocol: {protocol}" )
        

        # Render table
        row = {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "community_id": community_id,
        }
        query_data.append(row)        
        return query_data

    

if __name__ == "__main__":
    osquery.start_extension(name="community_id_extension", version="1.0.0")