from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

class CustomTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')

        h1 = self.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1/8')
        h2 = self.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2/8')
        h3 = self.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3/8')
        h4 = self.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4/8')  # BLOCKED

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

if __name__ == '__main__':
    setLogLevel('info')
    topo = CustomTopo()
    net = Mininet(topo=topo, controller=RemoteController)
    net.start()
    CLI(net)
    net.stop()
