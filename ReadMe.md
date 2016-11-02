# init-headphone tools

This repository contains tools for running and analyzing **hp.dll** from the
Windows driver of the headphone amplifier found in some Clevo laptops.

If you are only interested in the Linux driver go to: https://github.com/Unrud/init-headphone

## Running **hp.dll** on Linux (with [Wine](https://winehq.org))

  * Get the file **hp.dll** from the Windows driver.
  * Download this repository into a directory.
  * Make sure that **wine** and **setpci** are installed.
  * Download the [embeddable version of Python 3 for Windows x86](https://www.python.org/ftp/python/3.5.2/python-3.5.2-embed-win32.zip) and extract it.
  * Start **emulator.py** with root privileges: ``sudo python3 emulator.py``
  * Start **debugger.py** in Wine: ``wine python.exe debugger.py --host localhost hp.dll "InitHeadphone()"``
      * You can find an overview over all exported functions of **hp.dll** at
        the end of this document.

To create a log of all I/O port accesses start **emulator.py** with the
argument ``--log io.csv``. This log file can be read with **parser.py**.

## Analyzing **hp.dll** on Windows

  * The kernel driver **SvThANSP.sys** must be installed.
  * Get the file **hp.dll** from the Windows driver.
  * Download this repository into a directory.
  * Make sure that [Python](https://python.org) 3 for Windows x86 is installed.
  * Start **debugger.py**: ``python.exe debugger.py hp.dll "InitHeadphone()"``
    * If it doesn't work, it might help to change the variable ``CHILD_PYTHON``
      in the file **debugger.py** to point to a version of Python 2
      for Windows x86.
    * You can find an overview over all exported functions of **hp.dll** at
      the end of this document.

To create a log of all calls to [DeviceIoControl](https://msdn.microsoft.com/en-us/library/windows/desktop/aa363216%28v=vs.85%29.aspx)
start **debugger.py** with the argument ``--log calls.csv``.

## Exports of **hp.dll**

  * InitHeadphone()
  * Set_Mute(0)
  * Set_Mute(1)
  * Set_effect(0)
  * Set_effect(1)
  * Set_effect(2)
  * Set_effect(3)
  * Set_effect(4)
  * Set_effect(5)
  * Set_effect(6)
  * SetRecovery(?)
  * SvanspEnable(?)
