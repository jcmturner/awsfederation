Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |v|
    v.memory = 1024
    v.cpus = 1
  end
  config.vm.define "vault", primary: true do |vault|
    vault.vm.hostname = "vault.jtlan.co.uk"
    vault.vm.box = "centos/7"
    vault.vm.network "private_network", ip: "10.80.31.10", netmask: "255.255.0.0"
    vault.vm.provision :shell, path: "bootstrap.sh"
  end
end
