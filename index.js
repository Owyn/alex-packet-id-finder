const { protocol } = require('tera-data-parser')

const path = require('path')
const fs = require('fs')

protocol.load(require.resolve('tera-data'))

module.exports = function AlexPacketIdFinder(dispatch) {
    const command = dispatch.command
	
	let enabled = false
	let fullPacketDefList = [...new Set(findPacketDefList())]
	let filteredPacketDefList = fullPacketDefList
	let filterExpression = '.*'
	let filterKnownPackets = true
	let packetId = null
	let showCandidateJson = true
	
	function printMainStatus()
	{
		if (enabled) {
			command.message(`Packet id finder is now enabled (${packetId !== null ? 'only id ' + packetId : 'any id'}, regex /${filterExpression}/i).`)
			protocol.maps.get(dispatch.dispatch.protocolVersion).name.set(filterExpression, 0)
		} else {
			command.message(`Packet id finder is now disabled.`)
		}
	}
	
	command.add('fpi', (arg1, arg2) => {
		if (arg1 !== undefined) arg1 = ''+arg1
		if (arg2 !== undefined) arg2 = ''+arg2
		
		if (arg1 === undefined || ['d', 'disabled', 'false', 'no', '0'].includes(arg1.toLowerCase())) {
			enabled = false
			packetId = null
			filterExpression = '.*'
			rebuildFilteredPacketDefList()
			
			printMainStatus()
		} else if (/^\d+$/.test(arg1)) {
			enabled = true
			packetId = parseInt(arg1)
			filterExpression = '.*'
			rebuildFilteredPacketDefList()
			
			if (arg2 !== undefined) {
				filterExpression = arg2
			}
			
			printMainStatus()
		} else {
			if (arg1.toLowerCase() === 'json') {
				showCandidateJson = !showCandidateJson
				command.message(`Showing candidates as JSON is now ${showCandidateJson ? 'enabled' : 'disabled'}.`)
			} else if (['k', 'known', 'u', 'unk', 'unknown'].includes(arg1)) {
				filterKnownPackets = !filterKnownPackets
				rebuildFilteredPacketDefList()
				command.message(`Known packet filtering is now ${filterKnownPackets ? 'enabled' : 'disabled'}.`)
			} else {
				enabled = true
				packetId = null
				filterExpression = arg1
				rebuildFilteredPacketDefList()
				
				printMainStatus()
			}
		}
		
	})
	
	function findPacketDefList()
	{
		let result = []
		let basePath = require.resolve('tera-data')
		if (path.basename(basePath) === 'package.json') {
			basePath = path.dirname(basePath)
		}
		let defPath = path.join(basePath, 'protocol')
		let defFiles = fs.readdirSync(defPath)
		for (let file of defFiles) {
			let fullpath = path.join(defPath, file)

			let parsedName = path.basename(file).match(/^(\w+)\.(\d+)\.def$/)
			if (!parsedName) {
				continue
			}

			let name = parsedName[1]
			result.push(name)
		}
		
		return result
	}
	
	function isDefPerhapsWrong(name, packet, incoming, data, code) 
	{
		if (incoming && name.slice(0, 2) === 'C_') {
			return true
		}
		if (!incoming && name.slice(0, 2) === 'S_') {
			return true
		}
		
		let protocolVersion = dispatch.dispatch.protocolVersion
		let data2 = protocol.write(protocolVersion, name, '*', packet, undefined, undefined, code)
		if ((data.length != data2.length) || !data.equals(data2)) { // type Buffer
			return true
		} else {
			return false
		}
	}
	
	function rebuildFilteredPacketDefList()
	{
		filteredPacketDefList = []
		let re = new RegExp(filterExpression, 'i')
		for (let name of fullPacketDefList) {
			let code = protocol.maps.get(dispatch.dispatch.protocolVersion).name.get(name)
			let known = (code !== undefined && code !== null && code !== 0)
			if (known && filterKnownPackets) {
				//console.log("known " + name)
				continue
			}
			
			if (re.test(name)) {	
				//console.log(name)
				filteredPacketDefList.push(name)
			}
		}
	}
	
	function findPacketIds(code, data, incoming, fake)
	{
		let result = []
		
		for (let name of filteredPacketDefList) {
			if (incoming && name.slice(0, 2) === 'C_') {
				continue
			}
			if (!incoming && name.slice(0, 2) === 'S_') {
				continue
			}
			try {
				let protocolVersion = dispatch.dispatch.protocolVersion
				let packet = protocol.parse(protocolVersion, name, '*', data)
				let defPerhapsWrong = isDefPerhapsWrong(name, packet, incoming, data, code)
				
				if (!defPerhapsWrong) {
					result.push(name)
				}
			} catch(e) { //console.log(e)
			}
		}
		 
		return result
    }
	
	function loopBigIntToString(obj) {
		Object.keys(obj).forEach(key => {
			if (obj[key] && typeof obj[key] === 'object') loopBigIntToString(obj[key])
			else if (typeof obj[key] === "bigint") obj[key] = obj[key].toString()
		})
	}

    dispatch.hook('*', 'raw', { order: 999, type: 'all' }, (code, data, incoming, fake) => {
		if (!enabled) return
		if (packetId !== null && code != packetId) return
		
		let protocolVersion = dispatch.dispatch.protocolVersion
		let name = null
		let packet = null
		
		try {
			name = protocol.maps.get(protocolVersion).code.get(code)
		} catch(e) {
			name = undefined
		}
		
		let known = (name !== undefined && name !== null)
		
		if (!known || !filterKnownPackets) {
			let candidates = findPacketIds(code, data, incoming, fake)
			if (candidates.length > 0) {
				console.log(`Candidates for id ${code}: [${candidates.join(', ')}].`)
				command.message(`Candidates for id ${code}: [${candidates.join(', ')}].`)
				if (showCandidateJson) {
					for (let candidate of candidates) {
						let packet = protocol.parse(protocolVersion, candidate, '*', data)
						console.log(`${code} as ${candidate}:`)
						loopBigIntToString(packet)
						let json = JSON.stringify(packet, null, 4)
						console.log(json)
						command.message(json)
					}
				}
			}
		}
    })
}
