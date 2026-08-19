#pragma once

#include <protocols/ostrace/ostrace.hpp>

namespace blockfs {

inline bool tracingInitialized = false;

inline constinit protocols::ostrace::Event ostEvtGetLink{"libblockfs.getLink"};
inline constinit protocols::ostrace::Event ostEvtTraverseLinks{"libblockfs.traverseLinks"};
inline constinit protocols::ostrace::Event ostEvtRead{"libblockfs.read"};
inline constinit protocols::ostrace::Event ostEvtReadDir{"libblockfs.readDir"};
inline constinit protocols::ostrace::Event ostEvtWrite{"libblockfs.write"};
inline constinit protocols::ostrace::Event ostEvtWriteResizeFile{"libblockfs.write.resizeFile"};
inline constinit protocols::ostrace::Event ostEvtWriteCopyToCache{"libblockfs.write.copyToCache"};
inline constinit protocols::ostrace::Event ostEvtRawRead{"libblockfs.rawRead"};
inline constinit protocols::ostrace::Event ostEvtExt2AssignDataBlocks{"ext2.assignDataBlocks"};
inline constinit protocols::ostrace::Event ostEvtExt2ResizeEnsureBlocks{"ext2.resize.ensureBlocks"};
inline constinit protocols::ostrace::Event ostEvtExt2ResizeMemory{"ext2.resize.memory"};
inline constinit protocols::ostrace::Event ostEvtExt2ResizeSyncInode{"ext2.resize.syncInode"};
inline constinit protocols::ostrace::Event ostEvtExt2ManageInode{"ext2.manageInode"};
inline constinit protocols::ostrace::Event ostEvtExt2ManageInodeBitmap{"ext2.manageInodeBitmap"};
inline constinit protocols::ostrace::Event ostEvtExt2ManageFile{"ext2.manageFile"};
inline constinit protocols::ostrace::Event ostEvtExt2ManageFileWaitBlockMap{"ext2.manageFile.waitBlockMap"};
inline constinit protocols::ostrace::Event ostEvtExt2ManageFileAssignBlocks{"ext2.manageFile.assignBlocks"};
inline constinit protocols::ostrace::Event ostEvtExt2ManageFileWriteData{"ext2.manageFile.writeData"};
inline constinit protocols::ostrace::Event ostEvtExt2ManageFileUpdateMemory{"ext2.manageFile.updateMemory"};
inline constinit protocols::ostrace::Event ostEvtExt2WriteDataLookup{"ext2.writeData.lookup"};
inline constinit protocols::ostrace::Event ostEvtExt2WriteDataSectors{"ext2.writeData.sectors"};
inline constinit protocols::ostrace::Event ostEvtExt2ManageBlockBitmap{"ext2.manageBlockBitmap"};
inline constinit protocols::ostrace::Event ostEvtExt2AllocateBlocks{"ext2.allocateBlocks"};
inline constinit protocols::ostrace::Event ostEvtExt2AllocateInode{"ext2.allocateInode"};
inline constinit protocols::ostrace::UintAttribute ostAttrTime{"time"};
inline constinit protocols::ostrace::UintAttribute ostAttrNumBytes{"numBytes"};

inline protocols::ostrace::Vocabulary ostVocabulary{
	ostEvtGetLink,
	ostEvtTraverseLinks,
	ostEvtRead,
	ostEvtReadDir,
	ostEvtWrite,
	ostEvtWriteResizeFile,
	ostEvtWriteCopyToCache,
	ostEvtRawRead,
	ostEvtExt2AssignDataBlocks,
	ostEvtExt2ResizeEnsureBlocks,
	ostEvtExt2ResizeMemory,
	ostEvtExt2ResizeSyncInode,
	ostEvtExt2ManageInode,
	ostEvtExt2ManageInodeBitmap,
	ostEvtExt2ManageFile,
	ostEvtExt2ManageFileWaitBlockMap,
	ostEvtExt2ManageFileAssignBlocks,
	ostEvtExt2ManageFileWriteData,
	ostEvtExt2ManageFileUpdateMemory,
	ostEvtExt2WriteDataLookup,
	ostEvtExt2WriteDataSectors,
	ostEvtExt2ManageBlockBitmap,
	ostEvtExt2AllocateBlocks,
	ostEvtExt2AllocateInode,
	ostAttrTime,
	ostAttrNumBytes,
};

inline protocols::ostrace::Context ostContext{ostVocabulary};

} // namespace blockfs
