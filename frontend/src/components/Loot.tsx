import { useState, useEffect, useRef } from "react";
import type { MouseEvent as ReactMouseEvent } from "react";
import { useWebSocket } from "../hooks/useWebSocket";
import { useAuth } from "../contexts/AuthContext";
import { FaFolder, FaFolderOpen, FaFile, FaIdCard, FaChevronRight, FaChevronDown, FaCheckCircle, FaDownload, FaSpinner, FaThumbsUp, FaExclamationTriangle, FaSearch, FaArrowLeft, FaDatabase, FaFileCode, FaFileWord, FaFileExcel, FaFilePdf, FaFileImage, FaFileArchive, FaFileAlt, FaQuestion } from "react-icons/fa";
import { RiSkull2Fill } from "react-icons/ri";

interface LootFile {
  id: number;
  filename: string;
  originalPath: string;
  storedPath: string;
  md5Hash: string;
  fileSize: number;
  isOrganized: boolean;
  fileContent: string;
  fileType: string;
  createdAt: string;
}

interface LootFolder {
  name: string;
  path: string;
  isExpanded: boolean;
  files: LootFile[];
  subfolders: LootFolder[];
}

interface LootProps {
  isActive: boolean;
}

interface ContextMenuState {
  visible: boolean;
  x: number;
  y: number;
  file: LootFile | null;
  folder: LootFolder | null;
  isDirectory: boolean;
}

const initialContextMenuState: ContextMenuState = {
  visible: false,
  x: 0,
  y: 0,
  file: null,
  folder: null,
  isDirectory: false
};

const getFileKey = (file: LootFile): string | null => {
  const path = file.originalPath?.trim() || file.storedPath?.trim();
  if (path && path.length > 0) {
    return path.toLowerCase();
  }
  if (file.filename && file.filename.trim().length > 0) {
    return file.filename.trim().toLowerCase();
  }
  return null;
};

const organizeFilesIntoFolders = (files: LootFile[], expandedPaths: Set<string> = new Set<string>()): LootFolder[] => {
  const dedupedFiles: LootFile[] = [];
  const seenKeys = new Set<string>();

  files.forEach(file => {
    const key = getFileKey(file);
    if (key) {
      if (seenKeys.has(key)) {
        return;
      }
      seenKeys.add(key);
    }
    dedupedFiles.push(file);
  });

  const rootFolders: LootFolder[] = [];
  const unorganized: LootFile[] = [];
  
  // Track all directories that are represented in the folder structure
  const representedDirectories = new Set<string>();

  dedupedFiles.forEach(file => {
    if (file.originalPath && file.originalPath.trim() !== '') {
      // Remove the filename from the path to get just the directory path
      let directoryPath = file.originalPath;
      
      // If the path ends with the filename, remove it
      if (file.filename && directoryPath.endsWith(file.filename)) {
        directoryPath = directoryPath.substring(0, directoryPath.length - file.filename.length);
        // Remove trailing path separators
        directoryPath = directoryPath.replace(/[\\\/]+$/, '');
      }
      
      // Parse the directory path into components
      const pathParts = directoryPath.split(/[\\\/]/).filter(part => part && part.trim() !== '');
      
      if (pathParts.length > 0) {
        // Track all directory paths in the structure
        let buildPath = '';
        pathParts.forEach(part => {
          buildPath += (buildPath ? '\\' : '') + part;
          representedDirectories.add(buildPath.toLowerCase());
        });
        
        // Start from root level
        let currentLevel = rootFolders;
        let currentPath = '';

        // Build the directory structure
        let finalFolder = null;
        pathParts.forEach((part, index) => {
          currentPath += (currentPath ? '\\' : '') + part;
          
          let folder = currentLevel.find(f => f.name === part);
          if (!folder) {
            folder = {
              name: part,
              path: currentPath,
              isExpanded: expandedPaths.has(currentPath),
              files: [],
              subfolders: []
            };
            currentLevel.push(folder);
          } else {
            folder.isExpanded = expandedPaths.has(currentPath);
          }
          
          // Keep track of the final folder
          finalFolder = folder;
          
          // Move to next level for directories
          currentLevel = folder.subfolders;
        });
        
        // Add the file to the final directory
        if (finalFolder) {
          finalFolder.files.push(file);
        } else {
          unorganized.push(file);
        }
      } else {
        // No directory path, add to unorganized
        unorganized.push(file);
      }
    } else {
      unorganized.push(file);
    }
  });
  
  // Filter out directory entries that are already represented in the folder structure
  const filterDirectoryDuplicates = (folders: LootFolder[]): LootFolder[] => {
    return folders.map(folder => ({
      ...folder,
      files: folder.files.filter(file => {
        // If it's a directory type, check if it's already represented
        if (file.fileType === 'directory') {
          const dirPath = (file.originalPath || file.storedPath || file.filename).toLowerCase();
          // Normalize path separators
          const normalizedPath = dirPath.replace(/\//g, '\\');
          const isRepresented = representedDirectories.has(normalizedPath);
          return !isRepresented;
        }
        return true;
      }),
      subfolders: filterDirectoryDuplicates(folder.subfolders)
    }));
  };

  // Add unorganized files to a special folder if any exist
  if (unorganized.length > 0) {
    rootFolders.push({
      name: "Unorganized",
      path: "unorganized",
      isExpanded: expandedPaths.has("unorganized"),
      files: unorganized,
      subfolders: []
    });
  }

  // Filter out directory duplicates from all folders
  return filterDirectoryDuplicates(rootFolders);
};

const applyExpandedState = (folders: LootFolder[], expandedPaths: Set<string>): LootFolder[] => {
  return folders.map(folder => ({
    ...folder,
    isExpanded: expandedPaths.has(folder.path),
    subfolders: applyExpandedState(folder.subfolders, expandedPaths)
  }));
};

const findFolderPathForFile = (folders: LootFolder[], fileId: number): string | null => {
  for (const folder of folders) {
    if (folder.files.some(file => file.id === fileId)) {
      return folder.path;
    }
    const nestedPath = findFolderPathForFile(folder.subfolders, fileId);
    if (nestedPath) {
      return nestedPath;
    }
  }
  return null;
};

const expandPathHierarchy = (path: string, target: Set<string>) => {
  if (!path) {
    return;
  }
  const normalized = path.replace(/\//g, "\\");
  const parts = normalized.split("\\");
  let current = "";
  for (const part of parts) {
    if (!part) {
      continue;
    }
    current = current ? `${current}\\${part}` : part;
    target.add(current);
  }
};

export default function Loot({ isActive }: LootProps) {
  const { sendMessage, sendCommand, agents } = useWebSocket(isActive);
  const { user } = useAuth();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [lootData, setLootData] = useState<LootFolder[]>([]);
  const [loading, setLoading] = useState(false);
  const [downloadingFiles, setDownloadingFiles] = useState<Set<number>>(new Set<number>());
  const [downloadedFiles, setDownloadedFiles] = useState<Set<number>>(new Set<number>());
  const [collectingFiles, setCollectingFiles] = useState<Set<string>>(new Set<string>());
  const [exploringDirectories, setExploringDirectories] = useState<Set<string>>(new Set<string>());
  const [showLootData, setShowLootData] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set<string>());
  const [recentFileIds, setRecentFileIds] = useState<Set<number>>(new Set<number>());
  const [contextMenu, setContextMenu] = useState<ContextMenuState>(initialContextMenuState);

  const expandedPathsRef = useRef<Set<string>>(new Set<string>());
  const selectedAgentRef = useRef<string | null>(null);
  const knownFileIdsRef = useRef<Set<number>>(new Set<number>());
  const recentFileTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const collectingKeysRef = useRef<Set<string>>(new Set<string>());

  useEffect(() => {
    expandedPathsRef.current = expandedPaths;
  }, [expandedPaths]);

  useEffect(() => {
    selectedAgentRef.current = selectedAgent;
  }, [selectedAgent]);

  useEffect(() => {
    collectingKeysRef.current = collectingFiles;
  }, [collectingFiles]);

  useEffect(() => {
    if (recentFileTimerRef.current) {
      clearTimeout(recentFileTimerRef.current);
      recentFileTimerRef.current = null;
    }

    if (recentFileIds.size > 0) {
      recentFileTimerRef.current = setTimeout(() => {
        setRecentFileIds(new Set<number>());
        recentFileTimerRef.current = null;
      }, 6000);
    }

    return () => {
      if (recentFileTimerRef.current) {
        clearTimeout(recentFileTimerRef.current);
        recentFileTimerRef.current = null;
      }
    };
  }, [recentFileIds]);

  useEffect(() => {
    if (!contextMenu.visible) {
      return;
    }

    const handleDismiss = () => {
      setContextMenu(initialContextMenuState);
    };

    const handleKeydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setContextMenu(initialContextMenuState);
      }
    };

    window.addEventListener("click", handleDismiss);
    window.addEventListener("contextmenu", handleDismiss);
    window.addEventListener("keydown", handleKeydown);

    return () => {
      window.removeEventListener("click", handleDismiss);
      window.removeEventListener("contextmenu", handleDismiss);
      window.removeEventListener("keydown", handleKeydown);
    };
  }, [contextMenu.visible]);

  // Handle loot response from WebSocket
  useEffect(() => {
    if (!isActive) return;

    const handleLootResponse = (event: Event) => {
      try {
        const customEvent = event as CustomEvent;
        const data = customEvent.detail;

        if (data.type !== "loot_response") {
          return;
        }

        const incomingAgentId = data.agentId as string | undefined;
        if (!incomingAgentId) {
          return;
        }
        if (!selectedAgentRef.current || incomingAgentId !== selectedAgentRef.current) {
          return;
        }

        const files = (data.data as LootFile[]) || [];
        setLoading(false);

        const previousFileIds = knownFileIdsRef.current;
        const newFiles = files.filter(file => !previousFileIds.has(file.id));

        const expanded = new Set(expandedPathsRef.current);
        const organizedData = organizeFilesIntoFolders(files, expanded);

        if (newFiles.length > 0) {
          newFiles.forEach(file => {
            const folderPath = findFolderPathForFile(organizedData, file.id);
            if (folderPath) {
              expandPathHierarchy(folderPath, expanded);
            } else if (!file.originalPath || file.originalPath.trim() === "") {
              expandPathHierarchy("unorganized", expanded);
            }
          });
        }

        const finalExpanded = new Set(expanded);
        const updatedData = applyExpandedState(organizedData, finalExpanded);

        knownFileIdsRef.current = new Set(files.map(file => file.id));

        setLootData(updatedData);
        setExpandedPaths(finalExpanded);

        const completedKeys = new Set<string>();
        files.forEach(file => {
          const key = getFileKey(file);
          // File is complete if it has an md5Hash (content is stored in DB, not sent via websocket for performance)
          if (key && file.md5Hash && file.md5Hash.length > 0) {
            completedKeys.add(key);
          }
        });
        if (completedKeys.size > 0) {
          setCollectingFiles(prev => {
            const next = new Set(prev);
            completedKeys.forEach(key => next.delete(key));
            collectingKeysRef.current = next;
            return next;
          });
        }

        // Clear exploring directories when new loot data comes in
        setExploringDirectories(new Set());

        if (newFiles.length > 0) {
          setRecentFileIds(prev => {
            const next = new Set(prev);
            newFiles.forEach(file => next.add(file.id));
            return next;
          });
        }
      } catch (error) {
        console.error("Error parsing loot response:", error);
      }
    };

    // Listen for custom loot events
    window.addEventListener('loot-response', handleLootResponse);
    
    return () => {
      window.removeEventListener('loot-response', handleLootResponse);
    };
  }, [isActive]);

  const handleAgentSelect = (agentId: string) => {
    setSelectedAgent(agentId);
    selectedAgentRef.current = agentId;
    setLoading(true);
    setLootData([]);
    setShowLootData(true);
    setExpandedPaths(new Set<string>());
    expandedPathsRef.current = new Set<string>();
    setRecentFileIds(new Set<number>());
    if (recentFileTimerRef.current) {
      clearTimeout(recentFileTimerRef.current);
      recentFileTimerRef.current = null;
    }
    knownFileIdsRef.current = new Set<number>();
    setDownloadingFiles(new Set<number>());
    setDownloadedFiles(new Set<number>());
    setCollectingFiles(new Set<string>());
    collectingKeysRef.current = new Set<string>();
    setContextMenu(initialContextMenuState);
    
    // Request loot data for this agent
    sendMessage({
      type: "loot_request",
      agentId: agentId
    });
  };

  const handleBackToAgents = () => {
    setShowLootData(false);
    setSelectedAgent(null);
    selectedAgentRef.current = null;
    setLootData([]);
    setLoading(false);
    setExpandedPaths(new Set<string>());
    expandedPathsRef.current = new Set<string>();
    setRecentFileIds(new Set<number>());
    knownFileIdsRef.current = new Set<number>();
    if (recentFileTimerRef.current) {
      clearTimeout(recentFileTimerRef.current);
      recentFileTimerRef.current = null;
    }
    setDownloadingFiles(new Set<number>());
    setDownloadedFiles(new Set<number>());
    setCollectingFiles(new Set<string>());
    collectingKeysRef.current = new Set<string>();
    setContextMenu(initialContextMenuState);
  };


  const formatLastSeen = (lastSeen: string) => {
    const date = new Date(lastSeen);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins} minutes ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours} hours ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays} days ago`;
  };

  const filteredAgents = agents?.filter(agent => 
    agent.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    agent.ip.toLowerCase().includes(searchTerm.toLowerCase()) ||
    agent.os.toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  const getFileIcon = (file: LootFile) => {
    // Check if it's a directory first
    if (file.fileType === 'directory') {
      return <FaFolder style={{ marginRight: '8px', color: '#ffd700', fontSize: '14px' }} />;
    }
    
    // For files, use extension-based icons
    const extension = file.filename.split('.').pop()?.toLowerCase();
    
    switch (extension) {
      case 'js':
      case 'ts':
      case 'jsx':
      case 'tsx':
      case 'py':
      case 'java':
      case 'cpp':
      case 'c':
      case 'cs':
      case 'php':
      case 'rb':
      case 'go':
      case 'rs':
      case 'swift':
      case 'kt':
        return <FaFileCode style={{ marginRight: '8px', color: '#4CAF50', fontSize: '12px', zIndex: 2, position: 'relative' }} />;
      
      case 'doc':
      case 'docx':
      case 'rtf':
        return <FaFileWord style={{ marginRight: '8px', color: '#2196F3', fontSize: '12px', zIndex: 2, position: 'relative' }} />;
      
      case 'xls':
      case 'xlsx':
      case 'csv':
        return <FaFileExcel style={{ marginRight: '8px', color: '#4CAF50', fontSize: '12px', zIndex: 2, position: 'relative' }} />;
      
      case 'pdf':
        return <FaFilePdf style={{ marginRight: '8px', color: '#F44336', fontSize: '12px', zIndex: 2, position: 'relative' }} />;
      
      case 'jpg':
      case 'jpeg':
      case 'png':
      case 'gif':
      case 'bmp':
      case 'svg':
      case 'webp':
        return <FaFileImage style={{ marginRight: '8px', color: '#FF9800', fontSize: '12px', zIndex: 2, position: 'relative' }} />;
      
      case 'zip':
      case 'rar':
      case '7z':
      case 'tar':
      case 'gz':
        return <FaFileArchive style={{ marginRight: '8px', color: '#9C27B0', fontSize: '12px', zIndex: 2, position: 'relative' }} />;
      
      case 'exe':
      case 'msi':
      case 'app':
      case 'deb':
      case 'rpm':
        return <FaFileAlt style={{ marginRight: '8px', color: '#FF5722', fontSize: '12px', zIndex: 2, position: 'relative' }} />;
      
      default:
        return <FaFile style={{ marginRight: '8px', color: 'var(--text-secondary)', fontSize: '12px', zIndex: 2, position: 'relative' }} />;
    }
  };

  const openContextMenu = (event: ReactMouseEvent<HTMLDivElement>, file: LootFile) => {
    event.preventDefault();
    event.stopPropagation();

    const isDirectory = file.fileType === 'directory';
    const menuWidth = 180;
    const menuHeight = isDirectory ? 48 : 48; // Adjust if needed
    const viewportPadding = 8;

    let adjustedX = event.clientX;
    let adjustedY = event.clientY;

    if (adjustedX + menuWidth > window.innerWidth) {
      adjustedX = Math.max(viewportPadding, window.innerWidth - menuWidth - viewportPadding);
    }

    if (adjustedY + menuHeight > window.innerHeight) {
      adjustedY = Math.max(viewportPadding, window.innerHeight - menuHeight - viewportPadding);
    }

    setContextMenu({
      visible: true,
      x: adjustedX,
      y: adjustedY,
      file,
      folder: null,
      isDirectory
    });
  };

  const openFolderContextMenu = (event: ReactMouseEvent<HTMLDivElement>, folder: LootFolder) => {
    event.preventDefault();
    event.stopPropagation();

    const menuWidth = 180;
    const menuHeight = 48;
    const viewportPadding = 8;

    let adjustedX = event.clientX;
    let adjustedY = event.clientY;

    if (adjustedX + menuWidth > window.innerWidth) {
      adjustedX = Math.max(viewportPadding, window.innerWidth - menuWidth - viewportPadding);
    }

    if (adjustedY + menuHeight > window.innerHeight) {
      adjustedY = Math.max(viewportPadding, window.innerHeight - menuHeight - viewportPadding);
    }

    setContextMenu({
      visible: true,
      x: adjustedX,
      y: adjustedY,
      file: null,
      folder,
      isDirectory: true
    });
  };

  const toggleFolder = (folderPath: string) => {
    setExpandedPaths((prev) => {
      const updated = new Set(prev);
      if (updated.has(folderPath)) {
        updated.delete(folderPath);
      } else {
        updated.add(folderPath);
      }
      const normalized = new Set(updated);
      setLootData((prevLoot) => applyExpandedState(prevLoot, normalized));
      return normalized;
    });
  };

  const handleCollectFile = (file: LootFile) => {
    const agentId = selectedAgentRef.current;
    if (!agentId) {
      console.warn("Cannot collect loot without an active agent");
      return;
    }

    setContextMenu(initialContextMenuState);

    if (file.md5Hash && file.md5Hash.length > 0) {
      return;
    }

    const key = getFileKey(file);
    if (!key) {
      console.warn("Could not determine unique key for loot file:", file);
      return;
    }

    if (collectingKeysRef.current.has(key)) {
      return;
    }

    const sourcePath = (file.originalPath && file.originalPath.trim().length > 0)
      ? file.originalPath.trim()
      : (file.storedPath && typeof file.storedPath === "string" && file.storedPath.trim().length > 0
        ? file.storedPath.trim()
        : file.filename);

    if (!sourcePath || sourcePath.trim().length === 0) {
      console.warn("No path available to collect loot file:", file);
      return;
    }

    const escapedPath = sourcePath.replace(/"/g, '\\"');
    const needsQuoting = /\s/.test(escapedPath);
    const command = needsQuoting ? `get "${escapedPath}"` : `get ${escapedPath}`;

    setCollectingFiles(prev => {
      const next = new Set(prev);
      next.add(key);
      collectingKeysRef.current = next;
      return next;
    });

    sendCommand(agentId, command, user?.username || 'reaper');
  };

  const handleFileDownload = async (file: LootFile) => {
    if (downloadingFiles.has(file.id)) {
      return;
    }

    if (!file.md5Hash || file.md5Hash.length === 0) {
      console.warn('File not collected yet:', file.filename);
      return;
    }

    setDownloadingFiles((prev) => {
      const next = new Set(prev);
      next.add(file.id);
      return next;
    });

    try {
      // Fetch file content from server (not sent in list for performance)
      await new Promise<void>((resolve, reject) => {
        const handleFileContent = (event: Event) => {
          const customEvent = event as CustomEvent;
          const data = customEvent.detail;
          
          if (data.type === 'loot_file_response' && data.fileId === file.id) {
            window.removeEventListener('loot-file-response', handleFileContent);
            
            if (data.content) {
              try {
                const binaryString = atob(data.content);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                  bytes[i] = binaryString.charCodeAt(i);
                }
                const blob = new Blob([bytes], { type: 'application/octet-stream' });
                const url = window.URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = file.filename || 'loot-file';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                window.URL.revokeObjectURL(url);

                setDownloadedFiles((prev) => {
                  const next = new Set(prev);
                  next.add(file.id);
                  return next;
                });

                resolve();
              } catch (error) {
                reject(new Error(`Failed to decode file content: ${error}`));
              }
            } else {
              reject(new Error('No file content received'));
            }
          }
        };
        
        window.addEventListener('loot-file-response', handleFileContent);
        
        // Request file content
        sendMessage({
          type: 'loot_file_request',
          fileId: file.id
        });
        
        // Timeout after 30 seconds
        setTimeout(() => {
          window.removeEventListener('loot-file-response', handleFileContent);
          reject(new Error('File download timeout'));
        }, 30000);
      });
    } catch (error) {
      console.error('Failed to download file:', error);
      console.error(`❌ Failed to download file: ${error}`);
    } finally {
      setDownloadingFiles((prev) => {
        const next = new Set(prev);
        next.delete(file.id);
        return next;
      });
    }
  };

  const handleContextMenuCollect = () => {
    const targetFile = contextMenu.file;
    setContextMenu(initialContextMenuState);
    if (targetFile) {
      handleCollectFile(targetFile);
    }
  };

  const handleContextMenuExplore = () => {
    const targetFile = contextMenu.file;
    const targetFolder = contextMenu.folder;
    setContextMenu(initialContextMenuState);
    
    const agentId = selectedAgentRef.current;
    if (!agentId) {
      console.warn("Cannot explore directory without an active agent");
      return;
    }
    
    let directoryPath: string | null = null;
    
    // Handle file-based directory
    if (targetFile && targetFile.fileType === 'directory') {
      directoryPath = targetFile.originalPath || targetFile.storedPath || targetFile.filename;
    }
    
    // Handle folder-based directory
    if (targetFolder) {
      directoryPath = targetFolder.path;
    }
    
    if (directoryPath) {
      const command = `ls ${directoryPath}`;
      
      // Track directory exploration
      setExploringDirectories(prev => {
        const next = new Set(prev);
        next.add(directoryPath!);
        return next;
      });
      
      sendCommand(agentId, command, user?.username || 'reaper');
    }
  };

  const renderFolder = (folder: LootFolder, level: number = 0, isLast: boolean = true) => {
    const hasContent = folder.files.length > 0 || folder.subfolders.length > 0;
    const isExpanded = folder.isExpanded;
    const isRootLevel = level === 0;
    const isFolderExploring = exploringDirectories.has(folder.path);
    
    return (
      <div key={folder.path} style={{ 
        position: 'relative',
        marginLeft: level > 0 ? '20px' : '0'
      }}>
        {/* Tree lines for non-root items */}
        {level > 0 && (
          <>
            {/* Vertical line */}
            <div style={{
              position: 'absolute',
              left: '-20px',
              top: '0',
              bottom: isLast ? '12px' : '0',
              width: '1px',
              backgroundColor: 'var(--border-color)',
              zIndex: 1
            }} />
            {/* Horizontal line */}
            <div style={{
              position: 'absolute',
              left: '-20px',
              top: '12px',
              width: '20px',
              height: '1px',
              backgroundColor: 'var(--border-color)',
              zIndex: 1
            }} />
          </>
        )}
        
        <div 
          className="loot-folder" 
          onClick={() => hasContent && toggleFolder(folder.path)}
          onContextMenu={(e) => openFolderContextMenu(e, folder)}
          style={{ 
            display: 'flex', 
            alignItems: 'center', 
            padding: '6px 8px',
            cursor: hasContent ? 'pointer' : 'default',
            backgroundColor: isFolderExploring ? 'rgba(255, 215, 0, 0.12)' : (isExpanded ? 'var(--bg-tertiary)' : 'transparent'),
            borderRadius: '4px',
            marginBottom: '2px',
            border: isRootLevel ? '1px solid var(--border-color)' : 'none',
            borderLeft: isFolderExploring ? '2px solid #ffd700' : (isRootLevel ? 'none' : 'none'),
            transition: 'all 0.2s ease',
            position: 'relative',
            zIndex: 2
          }}
          onMouseEnter={(e) => {
            if (!isExpanded && !isFolderExploring) {
              e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
            }
          }}
          onMouseLeave={(e) => {
            if (!isExpanded && !isFolderExploring) {
              e.currentTarget.style.backgroundColor = 'transparent';
            } else if (isFolderExploring) {
              e.currentTarget.style.backgroundColor = 'rgba(255, 215, 0, 0.12)';
            }
          }}
        >
          {isFolderExploring && (
            <FaSpinner 
              style={{ 
                marginRight: '8px', 
                color: '#ffd700', 
                fontSize: '10px', 
                animation: 'spin 1s linear infinite' 
              }} 
              title="Exploring directory..." 
            />
          )}
          {!isFolderExploring && hasContent && (
            isExpanded ? <FaChevronDown style={{ marginRight: '8px', fontSize: '10px', color: 'var(--text-secondary)' }} /> 
                      : <FaChevronRight style={{ marginRight: '8px', fontSize: '10px', color: 'var(--text-secondary)' }} />
          )}
          {isExpanded ? <FaFolderOpen style={{ marginRight: '8px', color: '#ffd700', fontSize: '14px' }} /> 
                     : <FaFolder style={{ marginRight: '8px', color: isFolderExploring ? '#ffaa00' : '#ffd700', fontSize: '14px' }} />}
          <span style={{ 
            color: isRootLevel ? 'var(--text-primary)' : 'var(--text-secondary)', 
            fontWeight: isRootLevel ? '600' : '400',
            fontSize: isRootLevel ? '14px' : '13px'
          }}>
            {folder.name}
          </span>
          {folder.files.length > 0 && (
            <span style={{ 
              marginLeft: '8px', 
              color: 'var(--text-secondary)', 
              fontSize: '11px',
              backgroundColor: 'var(--bg-tertiary)',
              padding: '2px 6px',
              borderRadius: '10px'
            }}>
              {folder.files.length} file{folder.files.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        
        {isExpanded && (
          <div>
            {folder.subfolders.map((subfolder, subIndex) =>
              renderFolder(subfolder, level + 1, subIndex === folder.subfolders.length - 1 && folder.files.length === 0)
            )}
            {folder.files.map((file, fileIndex) => {
              const fileKey = getFileKey(file);
               const isDownloaded = file.md5Hash && file.md5Hash.length > 0;
              const isDownloading = downloadingFiles.has(file.id);
              const hasBeenDownloaded = downloadedFiles.has(file.id);
              const isCollecting = fileKey ? collectingFiles.has(fileKey) : false;
              const isLastFile = fileIndex === folder.files.length - 1;
              const isRecent = recentFileIds.has(file.id);
              const isExploring = file.fileType === 'directory' && exploringDirectories.has(file.originalPath || file.storedPath || file.filename);
              const recentHighlight = 'rgba(76, 175, 80, 0.12)';
              const collectingHighlight = 'rgba(33, 150, 243, 0.12)';
              const exploringHighlight = 'rgba(255, 215, 0, 0.12)';
              const baseBackground = isCollecting ? collectingHighlight : (isExploring ? exploringHighlight : (isRecent ? recentHighlight : 'transparent'));

              return (
                <div 
                  key={file.id} 
                  style={{ 
                    position: 'relative',
                    marginLeft: '20px',
                    display: 'flex',
                    alignItems: 'center',
                    padding: '4px 8px',
                    cursor: (isDownloaded && !isDownloading) ? 'pointer' : (isCollecting ? 'wait' : 'pointer'),
                    borderRadius: '4px',
                    marginBottom: '1px',
                    backgroundColor: baseBackground,
                    borderLeft: isCollecting ? '2px solid #2196F3' : (isRecent ? '2px solid #4CAF50' : '2px solid transparent'),
                    transition: 'background-color 0.2s ease, border-color 0.2s ease'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = baseBackground;
                  }}
                  onClick={() => {
                    const agentId = selectedAgentRef.current;
                    if (!agentId) {
                      console.warn("Cannot explore directory without an active agent");
                      return;
                    }

                    // Handle directory exploration
                    if (file.fileType === 'directory') {
                      const directoryPath = file.originalPath || file.storedPath || file.filename;
                      const command = `ls ${directoryPath}`;
                      
                      // Track directory exploration
                      setExploringDirectories(prev => {
                        const next = new Set(prev);
                        next.add(directoryPath);
                        return next;
                      });
                      
                      sendCommand(agentId, command, user?.username || 'reaper');
                      return;
                    }
                    
                    if (isDownloaded && !isDownloading) {
                      handleFileDownload(file);
                    } else if (!isDownloaded && !isCollecting) {
                      handleCollectFile(file);
                    }
                  }}
                  onContextMenu={(event) => openContextMenu(event, file)}
                >
                  {/* Tree lines for files */}
                  <div style={{
                    position: 'absolute',
                    left: '-20px',
                    top: '0',
                    bottom: isLastFile ? '12px' : '0',
                    width: '1px',
                    backgroundColor: 'var(--border-color)',
                    zIndex: 1
                  }} />
                  <div style={{
                    position: 'absolute',
                    left: '-20px',
                    top: '12px',
                    width: '20px',
                    height: '1px',
                    backgroundColor: 'var(--border-color)',
                    zIndex: 1
                  }} />
                  
                  {getFileIcon(file)}
                  {isCollecting && !isDownloaded && (
                    <FaSpinner 
                      style={{ 
                        marginRight: '6px', 
                        color: '#2196F3', 
                        fontSize: '10px', 
                        animation: 'spin 1s linear infinite' 
                      }} 
                      title="Collecting from agent..." 
                    />
                  )}
                  {isExploring && (
                    <FaSpinner 
                      style={{ 
                        marginRight: '6px', 
                        color: '#ffd700', 
                        fontSize: '10px', 
                        animation: 'spin 1s linear infinite' 
                      }} 
                      title="Exploring directory..." 
                    />
                  )}
                  {isDownloaded && (
                    <>
                      <FaCheckCircle style={{ marginRight: '6px', color: '#00ff00', fontSize: '10px' }} />
                      {isDownloading ? (
                        <FaSpinner 
                          style={{ 
                            marginRight: '6px', 
                            color: '#ffaa00', 
                            fontSize: '10px', 
                            animation: 'spin 1s linear infinite' 
                          }} 
                          title="Downloading..." 
                        />
                      ) : hasBeenDownloaded ? (
                        <FaCheckCircle 
                          style={{ 
                            marginRight: '6px', 
                            color: '#00aa00', 
                            fontSize: '10px' 
                          }} 
                          title="Downloaded to your computer" 
                        />
                      ) : (
                        <FaDownload 
                          style={{ 
                            marginRight: '6px', 
                            color: '#00ff00', 
                            fontSize: '10px', 
                            cursor: 'pointer' 
                          }} 
                          title="Click to download" 
                        />
                      )}
                    </>
                  )}
                  <span style={{ 
                    color: isDownloaded ? 'var(--text-primary)' : 'var(--text-secondary)', 
                    fontSize: '13px',
                    fontWeight: isDownloaded ? '500' : '400'
                  }}>
                    {file.filename}
                  </span>
                  <span style={{ 
                    marginLeft: '8px', 
                    color: 'var(--text-secondary)', 
                    fontSize: '11px',
                    fontFamily: 'monospace',
                    backgroundColor: 'var(--bg-tertiary)',
                    padding: '2px 6px',
                    borderRadius: '8px'
                  }}>
                    {Math.round(file.fileSize / 1024)}KB
                  </span>
                  {isDownloaded && (
                    <span style={{ 
                      marginLeft: '8px', 
                      color: '#00ff00', 
                      fontSize: '10px',
                      fontFamily: 'monospace',
                      fontWeight: 'bold',
                      backgroundColor: 'var(--bg-tertiary)',
                      padding: '2px 6px',
                      borderRadius: '8px'
                    }}>
                      {file.md5Hash.substring(0, 8)}...
                    </span>
                  )}
                  {!isDownloaded && (
                    <span style={{ 
                      marginLeft: '8px', 
                      color: 'var(--text-secondary)', 
                      fontSize: '10px',
                      fontFamily: 'monospace',
                      backgroundColor: 'var(--bg-tertiary)',
                      padding: '2px 6px',
                      borderRadius: '8px'
                    }}>
                      {isCollecting ? 'collecting...' : 'discovered'}
                    </span>
                  )}
                  {isRecent && !isCollecting && (
                    <span style={{ 
                      marginLeft: '8px', 
                      color: '#4CAF50', 
                      fontSize: '10px',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: '0.5px'
                    }}>
                      new
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  // Show agents list view
  if (!showLootData) {
    return (
      <div className="agents-container">
        <div className="agents-search">
          <div className="search-input-container">
            <FaSearch className="search-icon" />
            <input
              type="text"
              placeholder="Search agents..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
            />
          </div>
        </div>
        
        <table className="agents-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>IP</th>
              <th>OS</th>
            </tr>
          </thead>
          <tbody>
            {filteredAgents.map((agent) => (
               <tr 
                 key={agent.id}
                 className="agent-row"
                 onClick={() => handleAgentSelect(agent.id)}
               >
                 <td className="agent-name">{agent.name || <FaQuestion style={{ color: 'var(--text-secondary)' }} />}</td>
                 <td className="agent-ip">{agent.ip || <FaQuestion style={{ color: 'var(--text-secondary)' }} />}</td>
                 <td className="agent-os">{agent.os || <FaQuestion style={{ color: 'var(--text-secondary)' }} />}</td>
               </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  // Show loot data view
  return (
    <div className="agents-container">
       <div className="agents-search">
         <div className="search-input-container">
           <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button
              onClick={handleBackToAgents}
              style={{
                background: 'var(--bg-tertiary)',
                border: '1px solid var(--border-color)',
                color: 'var(--text-primary)',
                cursor: 'pointer',
                fontSize: '12px',
                padding: '6px',
                borderRadius: '6px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'all 0.2s ease'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--accent-red)';
                e.currentTarget.style.color = 'white';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
                e.currentTarget.style.color = 'var(--text-primary)';
              }}
            >
              <FaArrowLeft />
            </button>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
               <RiSkull2Fill style={{ color: 'var(--accent-red)', fontSize: '18px' }} />
               <h2 style={{ 
                 color: 'var(--text-primary)', 
                 margin: '0', 
                 fontSize: '18px',
                 fontWeight: '600'
               }}>
                 {selectedAgent}
               </h2>
             </div>
           </div>
         </div>
       </div>

       <div style={{
         backgroundColor: 'var(--bg-primary)',
         borderRadius: '8px',
         border: '1px solid var(--border-color)',
         overflow: 'hidden',
         height: 'calc(100vh - 120px)',
         overflowY: 'auto'
       }}>
        {loading && (
          <div style={{ 
            textAlign: 'center', 
            padding: '40px', 
            color: 'var(--text-secondary)',
            fontSize: '14px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px'
          }}>
            <FaSpinner style={{ animation: 'spin 1s linear infinite' }} />
            Loading loot data...
          </div>
        )}
        
        {!loading && lootData.length === 0 && (
          <div style={{ 
            textAlign: 'center', 
            padding: '40px', 
            color: 'var(--text-secondary)',
            fontSize: '14px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px'
          }}>
            <FaFile style={{ opacity: 0.5 }} />
            No loot files found for this agent.
          </div>
        )}
        
        {!loading && lootData.length > 0 && (
          <div style={{ padding: '16px' }}>
            {lootData.map((folder, index) => renderFolder(folder, 0, index === lootData.length - 1))}
          </div>
        )}
      </div>

      {contextMenu.visible && (contextMenu.file || contextMenu.folder) && (
        <div
          style={{
            position: 'fixed',
            top: contextMenu.y,
            left: contextMenu.x,
            zIndex: 10000,
            backgroundColor: 'var(--bg-secondary)',
            border: '1px solid var(--border-color)',
            borderRadius: '6px',
            boxShadow: '0 6px 18px rgba(0, 0, 0, 0.35)',
            padding: '6px 0',
            minWidth: '180px'
          }}
          onClick={(event) => event.stopPropagation()}
          onContextMenu={(event) => {
            event.preventDefault();
            event.stopPropagation();
          }}
        >
          {contextMenu.isDirectory ? (
            <button
              onClick={handleContextMenuExplore}
              style={{
                width: '100%',
                background: 'transparent',
                border: 'none',
                color: 'var(--text-primary)',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 14px',
                cursor: 'pointer',
                textAlign: 'left'
              }}
              onMouseEnter={(event) => {
                event.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
              }}
              onMouseLeave={(event) => {
                event.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <FaFolderOpen style={{ fontSize: '12px', color: '#ffd700' }} />
              Explore Directory
            </button>
          ) : (
            <button
              onClick={handleContextMenuCollect}
              style={{
                width: '100%',
                background: 'transparent',
                border: 'none',
                color: 'var(--text-primary)',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 14px',
                cursor: 'pointer',
                textAlign: 'left'
              }}
              onMouseEnter={(event) => {
                event.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
              }}
              onMouseLeave={(event) => {
                event.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <FaDatabase style={{ fontSize: '12px' }} />
              Collect from agent
            </button>
          )}
        </div>
      )}
    </div>
  );
}
