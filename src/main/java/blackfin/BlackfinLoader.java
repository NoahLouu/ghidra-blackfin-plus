/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package blackfin;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;


public class BlackfinLoader extends AbstractLibrarySupportLoader {

	// Classic Blackfin (BF5xx) boot stream block header (16 bytes, little-endian)
	private class BlockHeader {

		public static final int BFLAG_FINAL     = 0x8000;
		public static final int BFLAG_FIRST     = 0x4000;
		public static final int BFLAG_INDIRECT  = 0x2000;
		public static final int BFLAG_IGNORE    = 0x1000;
		public static final int BFLAG_INIT      = 0x800;
		public static final int BFLAG_CALLBACK  = 0x400;
		public static final int BFLAG_QUICKBOOT = 0x200;
		public static final int BFLAG_FILL      = 0x100;

		public static final int BFLAG_AUX       = 0x20;
		public static final int BFLAG_SAVE      = 0x10;

		// Classic Blackfin magic byte at header[3]
		public static final byte MAGIC_CLASSIC = (byte) 0xAD;

		int flags;
		byte checksum;
		byte magic;
		long targetAddress;
		long byteCount;
		long argument;
		byte[] rawHeader;

		BlockHeader(BinaryReader reader) throws IOException {
			rawHeader = reader.readByteArray(reader.getPointerIndex(), 16);
			flags = reader.readNextUnsignedShort();
			checksum = reader.readNextByte();
			magic = reader.readNextByte();
			targetAddress = reader.readNextUnsignedInt();
			byteCount = reader.readNextUnsignedInt();
			argument = reader.readNextUnsignedInt();
		}

		public boolean check() {
			if (magic != MAGIC_CLASSIC)
				return false;

			byte xorcksm = 0;
			for (int i=0; i<16; i++) {
				xorcksm = (byte) (xorcksm ^ rawHeader[i]);
			}

			return xorcksm == 0;
		}

		public String getComment() {
			return "Flags: "+Integer.toHexString(flags)+
					"; Argument: "+Long.toHexString(argument);
		}
	}

	// Blackfin+ (BF70x) boot stream block header (16 bytes, little-endian)
	// Reference: ADSP-BF70x Blackfin+ Processor Programming Reference, Chapter 4
	private class BlockHeaderPlus {

		public static final int BFLAG_FINAL    = 0x8000;
		public static final int BFLAG_FIRST    = 0x4000;
		public static final int BFLAG_INDIRECT = 0x2000;
		public static final int BFLAG_IGNORE   = 0x1000;
		public static final int BFLAG_INIT     = 0x0800;
		public static final int BFLAG_CALLBACK = 0x0400;
		public static final int BFLAG_FILL     = 0x0100;
		public static final int BFLAG_AUX      = 0x0020;
		public static final int BFLAG_SAVE     = 0x0010;

		// BF70x magic byte at header[3]
		public static final byte MAGIC_PLUS = (byte) 0x08;

		int flags;
		byte checksum;
		byte magic;
		long targetAddress;
		long byteCount;
		long argument;
		byte[] rawHeader;

		BlockHeaderPlus(BinaryReader reader) throws IOException {
			rawHeader = reader.readByteArray(reader.getPointerIndex(), 16);
			flags         = reader.readNextUnsignedShort();
			checksum      = reader.readNextByte();
			magic         = reader.readNextByte();
			targetAddress = reader.readNextUnsignedInt();
			byteCount     = reader.readNextUnsignedInt();
			argument      = reader.readNextUnsignedInt();
		}

		public boolean check() {
			if (magic != MAGIC_PLUS)
				return false;

			// XOR checksum of all 16 header bytes must be 0
			byte xorcksm = 0;
			for (int i = 0; i < 16; i++) {
				xorcksm = (byte) (xorcksm ^ rawHeader[i]);
			}
			return xorcksm == 0;
		}

		public boolean isFirst()    { return (flags & BFLAG_FIRST)    != 0; }
		public boolean isFinal()    { return (flags & BFLAG_FINAL)    != 0; }
		public boolean isInit()     { return (flags & BFLAG_INIT)     != 0; }
		public boolean isCallback() { return (flags & BFLAG_CALLBACK) != 0; }
		public boolean isIgnore()   { return (flags & BFLAG_IGNORE)   != 0; }
		public boolean isFill()     { return (flags & BFLAG_FILL)     != 0; }

		public String getComment() {
			return "BF70x Flags: " + Integer.toHexString(flags) +
					"; Argument: " + Long.toHexString(argument);
		}
	}

	@Override
	public String getName() {
		return "Blackfin boot stream";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {

		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < 16)
			return loadSpecs;

		BinaryReader reader = new BinaryReader(provider, true);

		// Try classic Blackfin (BF5xx/BF7xx) boot stream
		BlockHeader bh = new BlockHeader(reader);
		if (bh.check() && (bh.flags & BlockHeader.BFLAG_FIRST) != 0) {
			// BF702 (Blackfin+) uses classic LDR format but maps L1 at 0x11xxxxxx;
			// classic BF5xx maps L1 at 0xFFxxxxxx. Use target address to select language.
			boolean isBF702 = (bh.targetAddress >= 0x11000000L && bh.targetAddress <= 0x11FFFFFFL);
			List<QueryResult> queries = QueryOpinionService.query(getName(), "1", null);
			for (QueryResult result : queries) {
				boolean isPlus = result.pair.getLanguageID().toString().contains("blackfin+");
				if (isBF702 == isPlus) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
			}
			return loadSpecs;
		}

		// Try Blackfin+ (BF70x) boot stream (magic byte 0x08)
		reader.setPointerIndex(0);
		BlockHeaderPlus bhp = new BlockHeaderPlus(reader);
		if (bhp.check() && bhp.isFirst()) {
			List<QueryResult> queries = QueryOpinionService.query(getName(), "1", null);
			for (QueryResult result : queries) {
				if (result.pair.getLanguageID().toString().contains("blackfin+")) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
			}
		}

		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();

		BinaryReader reader = new BinaryReader(provider, true);

		// Detect boot stream variant from magic byte
		reader.setPointerIndex(0);
		byte magic = reader.readByte(3);

		if (magic == BlockHeaderPlus.MAGIC_PLUS) {
			loadBF70x(program, provider, reader, log, monitor);
		} else {
			loadClassic(program, provider, reader, log, monitor);
		}
	}

	// Load classic Blackfin (BF5xx) boot stream
	private void loadClassic(Program program, ByteProvider provider, BinaryReader reader,
			MessageLog log, TaskMonitor monitor) throws CancelledException, IOException {

		reader.setPointerIndex(0);
		long nextDxeOffset = 0;
		int i = 0;

		do {
			i++;
			long startOfBlock = reader.getPointerIndex();
			BlockHeader bh = new BlockHeader(reader);

			if (!bh.check()) {
				log.appendMsg("Incorrect block header encountered.");
				break;
			}

			Address target = program.getAddressFactory().getDefaultAddressSpace()
					.getAddress(bh.targetAddress);

			if (((bh.flags & BlockHeader.BFLAG_FIRST) != 0) && (startOfBlock != nextDxeOffset)) {
				log.appendMsg("Unexpected start of stream (BFLAG_FIRST) at offset " +
						Long.toHexString(startOfBlock));
				break;
			}
			if (((bh.flags & BlockHeader.BFLAG_FIRST) == 0) && (startOfBlock == nextDxeOffset)) {
				log.appendMsg("Missing BFLAG_FIRST on DXE.");
				break;
			}

			if (((bh.flags & BlockHeader.BFLAG_FIRST) != 0) && (startOfBlock == nextDxeOffset)) {
				setEntryPoint(program, target, "_entry");
				nextDxeOffset = bh.argument + reader.getPointerIndex();
			}

			if ((bh.flags & BlockHeader.BFLAG_INIT) != 0) {
				setEntryPoint(program, target, "_init" + i);
			}

			if ((bh.byteCount != 0) &&
					((bh.flags & BlockHeader.BFLAG_FILL) == 0) &&
					((bh.flags & BlockHeader.BFLAG_IGNORE) == 0)) {

				long offset = reader.getPointerIndex();
				reader.setPointerIndex(offset + bh.byteCount);
				createBlock(program, provider, "block" + i, target, offset, bh.byteCount,
						bh.getComment(), log, monitor);
			}

			if ((bh.flags & BlockHeader.BFLAG_CALLBACK) != 0) {
				log.appendMsg("Block " + i + " (BFLAG_CALLBACK) may contain encrypted/compressed data.");
			}

			if ((bh.flags & BlockHeader.BFLAG_IGNORE) != 0) {
				reader.setPointerIndex(reader.getPointerIndex() + bh.byteCount);
			}

			if ((bh.flags & BlockHeader.BFLAG_FILL) != 0) {
				createFillBlock(program, "block" + i, target, bh.byteCount, bh.argument, log, monitor);
			}

			if ((bh.flags & BlockHeader.BFLAG_FINAL) != 0) {
				long offset = reader.getPointerIndex();
				if (offset != nextDxeOffset)
					log.appendMsg("Boot stream end does not match DXE size.");
				if (offset < reader.length())
					log.appendMsg("Data present after end of boot stream at offset " + offset);
				break;
			}

		} while (true);
	}

	// Load Blackfin+ (BF70x) boot stream
	private void loadBF70x(Program program, ByteProvider provider, BinaryReader reader,
			MessageLog log, TaskMonitor monitor) throws CancelledException, IOException {

		reader.setPointerIndex(0);
		long nextDxeOffset = 0;
		int i = 0;

		do {
			i++;
			long startOfBlock = reader.getPointerIndex();
			BlockHeaderPlus bh = new BlockHeaderPlus(reader);

			if (!bh.check()) {
				log.appendMsg("BF70x: Incorrect block header at offset " +
						Long.toHexString(startOfBlock));
				break;
			}

			Address target = program.getAddressFactory().getDefaultAddressSpace()
					.getAddress(bh.targetAddress);

			if (bh.isFirst()) {
				if (startOfBlock == nextDxeOffset) {
					setEntryPoint(program, target, "_entry" + (i == 1 ? "" : Integer.toString(i)));
					// argument = offset of next DXE (from start of file in BF70x)
					nextDxeOffset = bh.argument;
				} else {
					log.appendMsg("BF70x: Unexpected BFLAG_FIRST at offset " +
							Long.toHexString(startOfBlock));
					break;
				}
			}

			if (bh.isInit()) {
				setEntryPoint(program, target, "_init" + i);
			}

			if (bh.isCallback()) {
				log.appendMsg("BF70x: Block " + i + " (BFLAG_CALLBACK) may be encrypted/compressed.");
			}

			if (!bh.isFill() && !bh.isIgnore() && bh.byteCount > 0) {
				long dataOffset = reader.getPointerIndex();
				reader.setPointerIndex(dataOffset + bh.byteCount);
				createBlock(program, provider, "block" + i, target, dataOffset, bh.byteCount,
						bh.getComment(), log, monitor);
			}

			if (bh.isIgnore() && bh.byteCount > 0) {
				reader.setPointerIndex(reader.getPointerIndex() + bh.byteCount);
			}

			if (bh.isFill() && bh.byteCount > 0) {
				createFillBlock(program, "block" + i, target, bh.byteCount, bh.argument, log, monitor);
			}

			if (bh.isFinal()) {
				break;
			}

		} while (reader.getPointerIndex() < reader.length());
	}

	private void createBlock(Program program, ByteProvider provider, String name, Address target,
			long fileOffset, long size, String comment, MessageLog log, TaskMonitor monitor) {
		try {
			MemoryBlock mem = program.getMemory().createInitializedBlock(name, target,
					provider.getInputStream(fileOffset), size, monitor, false);
			mem.setPermissions(true, true, true);
			mem.setComment(comment);
		} catch (MemoryConflictException e) {
			try {
				MemoryBlock mem = program.getMemory().createInitializedBlock(name, target,
						provider.getInputStream(fileOffset), size, monitor, true);
				mem.setPermissions(true, true, true);
				mem.setComment(comment);
			} catch (Exception f) {
				Msg.error(this, f.getMessage());
			}
		} catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
	}

	private void createFillBlock(Program program, String name, Address target, long size,
			long fillValue, MessageLog log, TaskMonitor monitor) {
		try {
			MemoryBlock mem = program.getMemory().createInitializedBlock(name, target,
					size, (byte) 0, monitor, false);
			mem.setPermissions(true, true, true);

			if (fillValue != 0) {
				Address pos = target;
				byte[] b = {
					(byte) fillValue,
					(byte) (fillValue >> 8),
					(byte) (fillValue >> 16),
					(byte) (fillValue >> 24)
				};
				while (pos.getOffset() < target.add(size).getOffset()) {
					mem.putBytes(pos, b);
					pos = pos.add(4);
				}
			}
		} catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
	}

	private void setEntryPoint(Program program, Address entry, String label) {
		try {
			program.getSymbolTable().createLabel(entry, label, SourceType.IMPORTED);
			program.getSymbolTable().addExternalEntryPoint(entry);
		} catch (InvalidInputException e) {
			Msg.error(this, e.getMessage());
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
		return super.getDefaultOptions(provider, loadSpec, domainObject,
				loadIntoProgram, mirrorFsLayout);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
