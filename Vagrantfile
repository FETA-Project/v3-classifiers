# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
    config.vm.box = "generic/oracle8"
    #config.vbguest.auto_update = false
    #config.vm.network "forwarded_port", guest: 80, host: 8080
    #config.vm.network "forwarded_port", guest: 443, host: 8443
    # config.vm.network "private_network", ip: "192.168.33.10"
    # config.vm.network "public_network"
  
    if Vagrant::Util::Platform.windows?
      # default windows share (SMB)
      config.vm.synced_folder "vagrant", "/vagrant", disabled: true
      config.vm.synced_folder ".", "/feta-repo"
    elsif Vagrant.has_plugin?("vagrant-sshfs") then
        config.vm.synced_folder ".", "/feta-repo", type: "sshfs"
    else
      config.vm.synced_folder ".", "/feta-repo", type: "rsync"
    end
  
    # Provider-specific configuration so you can fine-tune various
    # backing providers for Vagrant. These expose provider-specific options.
    # Example for VirtualBox:
  
     config.vm.provider "virtualbox" do |vb|
        # Display the VirtualBox GUI when booting the machine
        # vb.gui = true
  
        # Customize the amount of memory on the VM:
        vb.memory = "2048"
     end
     config.vm.provider "libvirt" do |vb|
        # Display the VirtualBox GUI when booting the machine
        # vb.gui = true
  
        # Customize the amount of memory on the VM:
        vb.memory = "2048"
     end
    # Install dependencies, DISTANCE system, simple GUI
    config.vm.provision "shell", path: "install-fetav3.sh"
  end