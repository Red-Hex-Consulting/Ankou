import { useState, useRef, useCallback, useEffect } from "react";
import {
  FaFolderOpen,
  FaPlus,
  FaUpload,
  FaPlay,
  FaTrashAlt,
  FaFileExport,
  FaTimes,
  FaStar,
  FaSync,
  FaSave,
  FaFolderMinus,
  FaFileAlt,
  FaCheckCircle,
} from "react-icons/fa";
import { Recipe, useRecipes } from "../hooks/useRecipes";
import "./RecipeManager.css";

interface RecipeManagerProps {
  onSelectRecipe: (prompt: string) => void;
  currentPrompt?: string;
}

export default function RecipeManager({ onSelectRecipe, currentPrompt }: RecipeManagerProps) {
  const {
    recipes,
    userRecipes,
    builtInRecipes,
    error,
    saveRecipe,
    deleteRecipe,
    importFiles,
    exportRecipe,
  } = useRecipes();

  const [isDragging, setIsDragging] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [formName, setFormName] = useState("");
  const [formPrompt, setFormPrompt] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const dropZoneRef = useRef<HTMLDivElement>(null);

  // Upload clicked
  const handleUploadClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  // Create clicked
  const handleCreateClick = useCallback(() => {
    setFormName("");
    setFormPrompt(currentPrompt || "");
    setIsCreating(true);
  }, [currentPrompt]);

  // Drag handlers
  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (dropZoneRef.current && !dropZoneRef.current.contains(e.relatedTarget as Node)) {
      setIsDragging(false);
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = Array.from(e.dataTransfer.files).filter(
      (f) => f.type === "text/plain" || f.name.endsWith(".txt")
    );

    if (files.length === 0) return;
    await importFiles(files);
  }, [importFiles]);

  const handleFileSelect = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files) return;

    await importFiles(Array.from(files));

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }, [importFiles]);

  const handleSave = async () => {
    if (!formName.trim() || !formPrompt.trim()) return;
    await saveRecipe(formName, formPrompt);
    setIsCreating(false);
    setFormName("");
    setFormPrompt("");
  };

  const handleDelete = async (recipe: Recipe) => {
    if (deleteConfirm === recipe.id) {
      await deleteRecipe(recipe);
      setDeleteConfirm(null);
    } else {
      setDeleteConfirm(recipe.id);
      setTimeout(() => setDeleteConfirm(null), 3000);
    }
  };

  const handleUseRecipe = (recipe: Recipe) => {
    onSelectRecipe(recipe.prompt);
  };

  return (
    <div
      className={`recipe-manager ${isDragging ? "dragging" : ""}`}
      ref={dropZoneRef}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {/* Drop overlay */}
      {isDragging && (
        <div className="recipe-drop-overlay">
          <FaUpload className="drop-icon" />
          <span>Drop .txt files to import</span>
        </div>
      )}

      {/* Top bar: title + Upload + Create */}
      <div className="recipe-header">
        <div className="recipe-header-title">
          <FaFileAlt className="header-icon" />
          <span>Prompt Recipes</span>
          <span className="recipe-count">{recipes.length}</span>
        </div>
        <div className="recipe-header-actions">
          <button className="recipe-icon-btn upload" onClick={handleUploadClick} title="Upload .txt files">
            <FaUpload />
          </button>
          <button className="recipe-icon-btn create" onClick={handleCreateClick} title="Create new recipe">
            <FaPlus />
          </button>
        </div>
      </div>

      {/* Error */}
      {error && <div className="recipe-error">{error}</div>}

      {/* Create form */}
      {isCreating && (
        <div className="recipe-create-form">
          <div className="recipe-form-header">
            <span>New Recipe</span>
            <button className="recipe-close-btn" onClick={() => setIsCreating(false)}>
              <FaTimes />
            </button>
          </div>
          <input
            type="text"
            placeholder="Recipe name"
            value={formName}
            onChange={(e) => setFormName(e.target.value)}
            autoFocus
          />
          <textarea
            placeholder="Prompt content..."
            value={formPrompt}
            onChange={(e) => setFormPrompt(e.target.value)}
            rows={4}
          />
          <div className="recipe-form-actions">
            <button className="recipe-btn secondary" onClick={() => setIsCreating(false)}>Cancel</button>
            <button
              className="recipe-btn primary"
              onClick={handleSave}
              disabled={!formName.trim() || !formPrompt.trim()}
            >
              <FaSave /> Save
            </button>
          </div>
        </div>
      )}

      {/* Recipe list */}
      <div className="recipe-list">
        {builtInRecipes.length > 0 && (
          <div className="recipe-section">
            <div className="recipe-section-label">
              <FaStar className="label-icon gold" /> Built-in
            </div>
            {builtInRecipes.map((recipe) => (
              <RecipeItem
                key={recipe.id}
                recipe={recipe}
                onUse={handleUseRecipe}
                onExport={exportRecipe}
              />
            ))}
          </div>
        )}

        {userRecipes.length > 0 && (
          <div className="recipe-section">
            <div className="recipe-section-label">
              <FaFileAlt className="label-icon" /> Your Recipes
            </div>
            {userRecipes.map((recipe) => (
              <RecipeItem
                key={recipe.id}
                recipe={recipe}
                onUse={handleUseRecipe}
                onDelete={handleDelete}
                onExport={exportRecipe}
                deleteConfirm={deleteConfirm === recipe.id}
              />
            ))}
          </div>
        )}

        {userRecipes.length === 0 && !isCreating && (
          <div className="recipe-empty">
            <FaUpload className="empty-icon" />
            <span>No custom recipes yet</span>
            <span className="empty-hint">
              Drag & drop .txt files here, or use the upload button above
            </span>
          </div>
        )}
      </div>

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".txt,text/plain"
        multiple
        onChange={handleFileSelect}
        style={{ display: "none" }}
      />
    </div>
  );
}


// ---------- Recipe Item ----------

interface RecipeItemProps {
  recipe: Recipe;
  onUse: (recipe: Recipe) => void;
  onDelete?: (recipe: Recipe) => void;
  onExport: (recipe: Recipe) => void;
  deleteConfirm?: boolean;
}

function RecipeItem({ recipe, onUse, onDelete, onExport, deleteConfirm }: RecipeItemProps) {
  const preview = recipe.prompt.length > 100
    ? recipe.prompt.slice(0, 100).trim() + "..."
    : recipe.prompt;

  return (
    <div className={`recipe-item ${recipe.isBuiltIn ? "builtin" : ""}`}>
      <div className="recipe-item-info" onClick={() => onUse(recipe)}>
        <span className="recipe-item-name">{recipe.name}</span>
        <span className="recipe-item-preview">{preview}</span>
      </div>
      <div className="recipe-item-actions">
        <button className="recipe-item-btn use" onClick={() => onUse(recipe)} title="Use this recipe">
          <FaPlay />
        </button>
        <button className="recipe-item-btn export" onClick={() => onExport(recipe)} title="Download as .txt">
          <FaFileExport />
        </button>
        {onDelete && !recipe.isBuiltIn && (
          <button
            className={`recipe-item-btn delete ${deleteConfirm ? "confirm" : ""}`}
            onClick={() => onDelete(recipe)}
            title={deleteConfirm ? "Click again to confirm delete" : "Delete"}
          >
            <FaTrashAlt />
          </button>
        )}
      </div>
    </div>
  );
}
