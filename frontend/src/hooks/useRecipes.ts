import { useState, useEffect, useCallback, useRef } from "react";
import { RED_TEAM_TRIAGE_PROMPT } from "../utils/prompts";

export interface Recipe {
  id: string;
  name: string;
  prompt: string;
  isBuiltIn?: boolean;
  fileName?: string;
}

const DB_NAME = "ankou-recipes-db";
const DB_VERSION = 1;
const STORE_NAME = "directory-handle";

// Built-in recipes that ship with the app
const BUILT_IN_RECIPES: Recipe[] = [
  {
    id: "builtin-red-team-triage",
    name: "Red Team Triage",
    prompt: RED_TEAM_TRIAGE_PROMPT,
    isBuiltIn: true,
  },
];

// IndexedDB helpers for persisting directory handle
async function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
  });
}

async function saveDirectoryHandle(handle: FileSystemDirectoryHandle): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const request = store.put(handle, "recipesDir");
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

async function loadDirectoryHandle(): Promise<FileSystemDirectoryHandle | null> {
  try {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const request = store.get("recipesDir");
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result || null);
    });
  } catch {
    return null;
  }
}

async function clearDirectoryHandle(): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const request = store.delete("recipesDir");
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

const STORAGE_KEY = "ankou-user-recipes";

export function useRecipes() {
  const [recipes, setRecipes] = useState<Recipe[]>([...BUILT_IN_RECIPES]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load recipes from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const userRecipes: Recipe[] = JSON.parse(stored);
        setRecipes([...BUILT_IN_RECIPES, ...userRecipes]);
      }
    } catch (err) {
      console.error("Failed to load recipes from storage:", err);
      setError("Failed to load saved recipes");
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Save recipes to localStorage whenever userRecipes changes
  const persistRecipes = useCallback((userRecipes: Recipe[]) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(userRecipes));
    } catch (err) {
      console.error("Failed to persist recipes:", err);
      setError("Failed to save recipes to browser storage");
    }
  }, []);

  // Save a new recipe
  const saveRecipe = useCallback(async (name: string, prompt: string): Promise<Recipe | null> => {
    const newRecipe: Recipe = {
      id: `user-${Date.now()}`,
      name: name.trim(),
      prompt,
      isBuiltIn: false,
    };

    setRecipes((prev) => {
      const builtIn = prev.filter(r => r.isBuiltIn);
      const user = prev.filter(r => !r.isBuiltIn);
      // If a recipe with the same name exists, replace it
      const filtered = user.filter((r) => r.name !== name.trim());
      const updatedUser = [...filtered, newRecipe];
      persistRecipes(updatedUser);
      return [...builtIn, ...updatedUser];
    });

    return newRecipe;
  }, [persistRecipes]);

  // Delete a recipe
  const deleteRecipe = useCallback(async (recipe: Recipe): Promise<boolean> => {
    if (recipe.isBuiltIn) return false;

    setRecipes((prev) => {
      const builtIn = prev.filter(r => r.isBuiltIn);
      const user = prev.filter(r => !r.isBuiltIn);
      const updatedUser = user.filter((r) => r.id !== recipe.id);
      persistRecipes(updatedUser);
      return [...builtIn, ...updatedUser];
    });

    return true;
  }, [persistRecipes]);

  // Import files (from drag-drop or file picker)
  const importFiles = useCallback(async (files: File[]): Promise<number> => {
    let imported = 0;
    const newRecipes: Recipe[] = [];

    for (const file of files) {
      if (!file.name.endsWith(".txt") && file.type !== "text/plain") continue;

      try {
        const content = await file.text();
        const name = file.name.replace(/\.txt$/i, "");
        newRecipes.push({
          id: `user-${Date.now()}-${imported}`,
          name,
          prompt: content,
          isBuiltIn: false,
        });
        imported++;
      } catch (err) {
        console.error(`Failed to import ${file.name}:`, err);
      }
    }

    if (newRecipes.length > 0) {
      setRecipes((prev) => {
        const builtIn = prev.filter(r => r.isBuiltIn);
        const user = prev.filter(r => !r.isBuiltIn);
        // Deduplicate by name if necessary or just append
        const updatedUser = [...user, ...newRecipes];
        persistRecipes(updatedUser);
        return [...builtIn, ...updatedUser];
      });
    }

    return imported;
  }, [persistRecipes]);

  // Export a recipe (download as .txt)
  const exportRecipe = useCallback((recipe: Recipe) => {
    const blob = new Blob([recipe.prompt], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${recipe.name}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, []);

  const userRecipes = recipes.filter((r) => !r.isBuiltIn);
  const builtInRecipes = recipes.filter((r) => r.isBuiltIn);

  return {
    recipes,
    userRecipes,
    builtInRecipes,
    isLoading,
    error,
    saveRecipe,
    deleteRecipe,
    importFiles,
    exportRecipe,
  };
}

