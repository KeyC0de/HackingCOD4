<h1 align="center">
	<a href="https://github.com/KeyC0de/HackingCOD4">Hacking COD4</a>
</h1>
<hr>

1. We loop through the process list to find our target process.
2. `OpenProcess( targetProcess )` give `PROCESS_ALL_ACCESS` such that our program obtains full access to the target process (ie both read and write privileges and more)
3. Use CheatEngine or some other debugger program to find your target address to intercept. For example you're in COD4, you can see your current weapon's screen's ammo is 300 and you want to set it to 50 (say). Then you'd search for float or integer 300 in CheatEngine to find the right address (sorry this isn't a CheatEngine tutorial). When you find the address move on.
4. Write into that address using `WriteProcessMemory`. This is where you'd right the 50. Or you can `ReadProcessMemory` instead.

It's up to you. The code is very short and commented out. You can also test the `convenientWrappers` section for more cool stuff, but not necessary. All you need lies inside the main function, your game (it can be any game, not just COD4 - just change `processName` to the game's title)and CheatEngine. The rest is just icing on the cake.

Generic process/game hacking application. This time the victim being Call of Duty 4.

I used Windows 8.1 x86_64, Visual Studio 2017, Modern C++17 to build the project. It should work on other platforms as well.



# Contribute

Please submit any bugs you find through GitHub repository 'Issues' page with details describing how to replicate the problem. If you liked it or you learned something new give it a star, clone it, laugh at it, contribute to it whatever. I appreciate all of it. Enjoy.


# License

Distributed under the GNU GPL V3 License. See "GNU GPL license.txt" for more information.


# Contact

email: *nik.lazkey@gmail.com*</br>
website: *www.keyc0de.net*


# Acknowledgements

Microsoft docs - [Process Status API](https://docs.microsoft.com/en-us/windows/win32/psapi/process-status-helper)
