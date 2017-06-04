Name:           kbfd
Version:        1.0.0
Release:        %{?release:%{release}}%{!?release:eng}
Summary:        BFD(Bidirectional Forwarding Detection) for Linux

Group:          System Environment/Kernel
License:        GPL
Source0:	Makefile
Source1:        kbfd.h            
Source2:        kbfd_log.c   
Source3:        kbfd_netlink.c  
Source4:        kbfd_packet.h   
Source5:        kbfd_v4v6.c
Source6:        kbfd_interface.c  
Source7:        kbfd_log.h   
Source8:        kbfd_netlink.h  
Source9:        kbfd_session.c  
Source10:       kbfd_v4v6.h
Source11:       kbfd_interface.h  
Source12:       kbfd_main.c  
Source13:       kbfd_packet.c   
Source14:       kbfd_session.h
Source15:       proc_compat.h
Source16:       proc_compat.c
Source17:       COPYING
Source18:       kbfd_feature.h
Source19:       kbfd_feature.c

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires(post,preun):	/sbin/depmod, /sbin/rmmod, /usr/bin/readlink

%description
Kernel module implementing the BFD protocol.

%package devel
Summary: kbfd development

%description devel
Provides the files necessary for BFD application development.

%prep

%setup -T -c


%build
%{__make} %{?_smp_mflags} all

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/kbfd
cp COPYING $RPM_BUILD_ROOT/usr/share/doc/kbfd
make "DESTDIR=$RPM_BUILD_ROOT" install
strip --strip-debug $RPM_BUILD_ROOT/lib/modules/*/kernel/drivers/net/kbfd.ko
rm -f "$RPM_BUILD_ROOT"%{_libdir}/*.la

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/lib/modules/*/kernel/drivers/net/kbfd.ko
/usr/share/doc/kbfd

%files devel
%defattr(-,root,root)
%{_includedir}/kbfd
%{_bindir}/kbfd.proc

%post
rmmod kbfd 2>/dev/null || :
depmod $(readlink /lib/modules/$KERNEL_VER)
true

%preun
rmmod kbfd 2>/dev/null || :
depmod $(readlink /lib/modules/$KERNEL_VER)
true
