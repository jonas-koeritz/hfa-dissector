# hfa-dissector
Wireshark Lua dissector for the Siemens/Unify CorNet-IP (HFA) protocol

# What is working and what

- [X] Basic Packet dissection
  - [X] Decode Key Presses
  - [X] Decode Display Updates
  - [X] Decode Stimulus Menus
  - [X] Decode basic device control commands
- [X] Basic Stimulus Packet dissection
  - [ ] Understand the complete Stimulus protocol
- [ ] Understand all message types
- [ ] Understand the HFA Login/Register process


# How to use

- Download [hfa.lua](hfa.lua)
- Put it in your Wireshark plugins folder.
  - On Windows: `C:\Users\<username>\AppData\Roaming\Wireshark\plugins`
  - On Linux: `~/.wireshark/plugins`

# Hints

Feel free to leave any knowledge as an issue
