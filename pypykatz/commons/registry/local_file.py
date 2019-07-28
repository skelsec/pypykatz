

if __name__ == '__main__':
	from aiowinreg.hive import AIOWinRegHive
	
	with open('C:\\Users\\victim\\Desktop\\aiowinreg\\1_SAM.reg', 'rb') as f:
		hive = AIOWinRegHive(f)
		sam = SAM(hive)
		sam.dump()
		
		